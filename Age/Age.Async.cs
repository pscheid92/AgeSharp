using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

public static partial class Age
{
    /// <summary>
    /// Asynchronously encrypts <paramref name="input"/> into binary age format
    /// (or ASCII armor per <paramref name="options"/>) and writes the result to
    /// <paramref name="output"/>. Every stream operation is genuinely asynchronous
    /// — no blocking I/O on either stream.
    /// </summary>
    /// <param name="input">The plaintext source. Read once, start to end.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="recipients">One or more recipients. Must all produce the same label set.</param>
    /// <param name="options">Encryption options; defaults are used when null.</param>
    /// <param name="cancellationToken">Cancels the operation between stream reads/writes.</param>
    /// <exception cref="ArgumentException">No recipients were supplied.</exception>
    /// <remarks>
    /// A plugin recipient still performs synchronous child-process I/O while wrapping,
    /// even on this path (the plugin interfaces are synchronous, matching the reference
    /// implementation). This runs during the eager setup, before any stream I/O.
    /// </remarks>
    public static async Task EncryptAsync(Stream input, Stream output, IReadOnlyList<IRecipient> recipients,
                                          AgeOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        if (recipients.Count == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        // EncryptReader builds the header eagerly and touches neither stream, so it
        // is safe to create synchronously before awaiting. The span is consumed by
        // that synchronous call and never crosses an await.
        var recipientArray = recipients as IRecipient[] ?? [.. recipients];
        var stream = EncryptReader(input, options ?? AgeOptions.Default, recipientArray);

        await using (stream.ConfigureAwait(false))
            await stream.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Asynchronously decrypts an age-encrypted <paramref name="input"/> into
    /// <paramref name="output"/>. Armored input is auto-detected when the source
    /// is seekable. Every stream operation is genuinely asynchronous.
    /// </summary>
    /// <param name="input">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <param name="options">Parsing options; defaults are used when null.</param>
    /// <param name="cancellationToken">Cancels the operation between stream reads/writes.</param>
    /// <exception cref="ArgumentException">No identities were supplied.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC or a payload chunk failed authentication.</exception>
    public static async Task DecryptAsync(Stream input, Stream output, IReadOnlyList<IIdentity> identities,
                                          AgeOptions? options = null, CancellationToken cancellationToken = default)
    {
        var stream = await OpenReadAsync(input, identities, options, cancellationToken).ConfigureAwait(false);

        await using (stream.ConfigureAwait(false))
            await stream.CopyToAsync(output, cancellationToken).ConfigureAwait(false);

        // Touch output even when the plaintext is empty — matters for lazy-creating
        // writers that only materialize on first write.
        await output.WriteAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Asynchronously opens an age-encrypted <paramref name="source"/> for reading
    /// its plaintext. The header is parsed and its MAC verified before the returned
    /// stream is produced; payload decryption is lazy and asynchronous.
    /// </summary>
    /// <remarks>
    /// Unlike the synchronous <see cref="OpenRead(Stream, ReadOnlySpan{IIdentity})"/>,
    /// the returned stream is <b>forward-only</b> (<see cref="Stream.CanSeek"/> is
    /// false); the seekable random-access path is synchronous only. A seekable
    /// armored source is materialized (its dearmored bytes are buffered in memory).
    /// </remarks>
    /// <param name="source">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <param name="options">Parsing options; defaults are used when null.</param>
    /// <param name="cancellationToken">Cancels the header read.</param>
    /// <exception cref="ArgumentException">No identities were supplied.</exception>
    public static async ValueTask<Stream> OpenReadAsync(Stream source, IReadOnlyList<IIdentity> identities,
                                                        AgeOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identities);
        if (identities.Count == 0)
            throw new ArgumentException("at least one identity is required", nameof(identities));

        options ??= AgeOptions.Default;

        var (binaryInput, needsDispose) = await DeArmorIfNeededAsync(source, options, cancellationToken).ConfigureAwait(false);
        byte[]? payloadKey = null;

        try
        {
            var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
            await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);

            // The header is now buffered, so unwrapping is pure/synchronous and the
            // span never crosses an await.
            var identityArray = identities as IIdentity[] ?? [.. identities];
            var fileKey = UnwrapHeader(reader, identityArray);

            try
            {
                var payloadNonce = new byte[PayloadNonceSize];
                var read = await reader.ReadPayloadBytesAsync(payloadNonce, cancellationToken).ConfigureAwait(false);
                if (read != PayloadNonceSize)
                    throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {read} bytes");

                payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fileKey);
            }

            return new DecryptStream(payloadKey, binaryInput, needsDispose);
        }
        catch
        {
            if (payloadKey is not null) CryptographicOperations.ZeroMemory(payloadKey);
            if (needsDispose) await binaryInput.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async ValueTask<(Stream binaryInput, bool needsDispose)> DeArmorIfNeededAsync(Stream input, AgeOptions options, CancellationToken cancellationToken)
    {
        // Armor is only detectable on a seekable source. Read the armored bytes into
        // memory asynchronously, then dearmor them in memory (synchronously) so no
        // blocking I/O ever touches the caller's stream — mirroring the sync path's
        // materialization.
        if (input.CanSeek && await AsciiArmor.IsArmoredAsync(input, cancellationToken).ConfigureAwait(false))
        {
            using var armored = new MemoryStream();
            await input.CopyToAsync(armored, cancellationToken).ConfigureAwait(false);
            armored.Position = 0;

            using var dearmored = AsciiArmor.Dearmor(armored, options.MaxArmorLineBytes);
            var buffer = new MemoryStream();
            dearmored.CopyTo(buffer);
            buffer.Position = 0;
            return (buffer, true);
        }

        return (input, false);
    }
}
