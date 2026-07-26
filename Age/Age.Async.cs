using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

public static partial class Age
{
    /// <summary>
    ///     Asynchronously encrypts <paramref name="input" /> into binary age format
    ///     (or ASCII armor per <paramref name="options" />) and writes the result to
    ///     <paramref name="output" />. Every stream operation is genuinely asynchronous
    ///     — no blocking I/O on either stream.
    /// </summary>
    /// <exception cref="ArgumentException">No recipients were supplied.</exception>
    /// <remarks>
    ///     A plugin recipient still performs synchronous child-process I/O while wrapping,
    ///     even on this path (the plugin interfaces are synchronous, matching the reference
    ///     implementation). This runs during the eager setup, before any stream I/O.
    /// </remarks>
    public static async Task EncryptAsync(Stream input, Stream output, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        var stream = EncryptReader(input, recipients, options);

        await using (stream.ConfigureAwait(false))
        {
            await stream.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    ///     Asynchronously decrypts an age-encrypted <paramref name="input" /> into
    ///     <paramref name="output" />. Armored input is auto-detected on any
    ///     source, seekable or not. Every stream operation is genuinely asynchronous.
    /// </summary>
    /// <exception cref="ArgumentException">No identities were supplied.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC or a payload chunk failed authentication.</exception>
    public static async Task DecryptAsync(Stream input, Stream output, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        var stream = await DecryptReaderAsync(input, identities, options, cancellationToken).ConfigureAwait(false);

        await using (stream.ConfigureAwait(false))
        {
            await stream.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        }

        // A lazy-creating writer must still materialize.
        await output.WriteAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///     Asynchronously opens an age-encrypted <paramref name="source" /> for reading
    ///     its plaintext. The header is parsed and its MAC verified before the returned
    ///     stream is produced; payload decryption is lazy and asynchronous.
    /// </summary>
    /// <remarks>
    ///     Behaves as <see cref="DecryptReader" /> does:
    ///     <see cref="Stream.CanSeek" /> mirrors the source, and opening a seekable one
    ///     authenticates the plaintext length by decrypting the final chunk. Every step,
    ///     including that authentication and each chunk read, is asynchronous.
    /// </remarks>
    /// <exception cref="ArgumentException">No identities were supplied.</exception>
    public static async ValueTask<Stream> DecryptReaderAsync(Stream source, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        var identityArray = Materialize(identities, nameof(identities), "identity");
        options ??= AgeDecryptOptions.Default;

        var (binaryInput, needsDispose) = await DeArmorIfNeededAsync(source, options, cancellationToken).ConfigureAwait(false);
        byte[]? payloadKey = null;

        try
        {
            var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
            await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);

            var fileKey = new byte[FileKeySize];
            UnwrapHeader(reader, identityArray, fileKey);

            try
            {
                var payloadNonce = new byte[PayloadNonceSize];
                var read = await reader.ReadPayloadBytesAsync(payloadNonce, cancellationToken).ConfigureAwait(false);
                if (read != PayloadNonceSize)
                    throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {read} bytes");

                payloadKey = new byte[PayloadKeySize];
                CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fileKey);
            }

            return binaryInput.CanSeek
                ? await SeekableDecryptStream.CreateAsync(payloadKey, binaryInput, binaryInput.Position,
                    needsDispose, cancellationToken).ConfigureAwait(false)
                : new DecryptStream(payloadKey, binaryInput, needsDispose);
        }
        catch
        {
            if (payloadKey is not null) CryptographicOperations.ZeroMemory(payloadKey);
            if (needsDispose) await binaryInput.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    ///     Asynchronous counterpart to
    ///     <see cref="EncryptDetached(Stream, Stream, Stream, IReadOnlyList{IRecipient})" />.
    /// </summary>
    /// <remarks>
    ///     No options parameter, for the same reason the synchronous form has none: armor wraps a
    ///     whole age file, which a detached header and payload are not.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static async Task EncryptDetachedAsync(Stream input, Stream headerOutput, Stream payloadOutput,
                                                  IReadOnlyList<IRecipient> recipients,
                                                  CancellationToken cancellationToken = default)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));

        try
        {
            // The header is built in memory either way, so writing it out is a single
            // asynchronous write rather than a second serialisation path.
            using var headerBytes = new MemoryStream();
            header.WriteTo(headerBytes, fileKey);
            await headerOutput.WriteAsync(headerBytes.GetBuffer().AsMemory(0, (int)headerBytes.Length),
                                          cancellationToken).ConfigureAwait(false);

            var payloadNonce = new byte[PayloadNonceSize];
            RandomNumberGenerator.Fill(payloadNonce);
            var payloadKey = new byte[PayloadKeySize];
            CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);

            var payloadStream = new EncryptStream([], payloadNonce, payloadKey, input);
            await using (payloadStream.ConfigureAwait(false))
                await payloadStream.CopyToAsync(payloadOutput, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    ///     Asynchronous counterpart to
    ///     <see cref="DecryptDetached(Stream, Stream, Stream, IReadOnlyList{IIdentity}, AgeDecryptOptions)" />.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    public static async Task DecryptDetachedAsync(Stream headerInput, Stream payloadInput, Stream output,
                                                  IReadOnlyList<IIdentity> identities,
                                                  AgeDecryptOptions? options = null,
                                                  CancellationToken cancellationToken = default)
    {
        var identityArray = Materialize(identities, nameof(identities), "identity");
        options ??= AgeDecryptOptions.Default;

        var reader = new HeaderReader(headerInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
        await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);

        // Buffered, so unwrapping is pure and no span crosses an await.
        var fileKey = new byte[FileKeySize];
        UnwrapHeader(reader, identityArray, fileKey);

        try
        {
            var payloadNonce = new byte[PayloadNonceSize];
            var read = await payloadInput.ReadAtLeastAsync(payloadNonce, PayloadNonceSize, false, cancellationToken)
                                         .ConfigureAwait(false);

            if (read != PayloadNonceSize)
                throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {read} bytes");

            var payloadKey = new byte[PayloadKeySize];
            CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);

            var decryptStream = new DecryptStream(payloadKey, payloadInput, false);
            await using (decryptStream.ConfigureAwait(false))
                await decryptStream.CopyToAsync(output, cancellationToken).ConfigureAwait(false);

            // A lazy-creating writer must still materialize.
            await output.WriteAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    ///     Asynchronous counterpart to <see cref="ReadHeader" />. Present because reading a
    ///     header is I/O; the encrypt-side factories have no async form because their setup
    ///     touches no stream.
    /// </summary>
    /// <remarks>The result is <b>unverified</b> — see <see cref="ReadHeader" />.</remarks>
    /// <param name="source">The age-encrypted source.</param>
    /// <param name="options">Parsing options (the header-size limits); defaults when null.</param>
    /// <param name="cancellationToken">Cancels the header read.</param>
    public static ValueTask<AgeHeader> ReadHeaderAsync(Stream source, AgeDecryptOptions? options = null,
                                                       CancellationToken cancellationToken = default) =>
        AgeHeader.ParseAsync(source, options ?? AgeDecryptOptions.Default, cancellationToken);

    private static async ValueTask<(Stream binaryInput, bool needsDispose)> DeArmorIfNeededAsync(Stream input, AgeDecryptOptions options, CancellationToken cancellationToken)
    {
        var (source, isArmored) = await AsciiArmor.DetectAsync(input, options.RequireArmor, cancellationToken).ConfigureAwait(false);

        return isArmored
            ? (
                await AsciiArmor.DearmorAsync(source, options.MaxArmorLineBytes, cancellationToken)
                    .ConfigureAwait(false), true)
            : (source, false);
    }
}