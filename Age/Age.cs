using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     Top-level entry point for encrypting and decrypting data in the age format.
///     All streaming APIs are memory-bounded: a 1 GiB input uses the same working
///     set as a 1 MB input (two 64 KiB chunk buffers rented from <c>ArrayPool</c>).
///     This holds for ASCII-armored input too — armor is decoded a line at a time
///     rather than buffered — and on the asynchronous paths as well as the
///     synchronous ones.
/// </summary>
/// <remarks>
///     Four members return a <see cref="Stream" />: <see cref="EncryptReader" /> and
///     <see cref="DecryptReader" /> are pull (you read, setup is eager),
///     <see cref="EncryptWriter" /> and <see cref="DecryptWriter" /> are push in the spirit of
///     <see cref="System.IO.Compression.GZipStream" /> (disposing finalizes the transfer).
///     <para>
///         Recipients and identities are always an <see cref="IReadOnlyList{T}" /> and options
///         always come last, optional — the async members add only a
///         <see cref="CancellationToken" />. At a call site that is usually a collection
///         expression: <c>Age.Encrypt(input, output, [recipient])</c>.
///     </para>
/// </remarks>
public static partial class Age
{
    private const int FileKeySize = 16;
    internal const int PayloadNonceSize = 16;
    internal const int PayloadKeySize = 32;

    /// <summary>Encrypts <paramref name="input" /> to <paramref name="output" />, e.g. <c>Encrypt(in, out, [recipient])</c>.</summary>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    /// <exception cref="AgeException">Recipients have mismatched labels, or a passphrase was combined with other recipients.</exception>
    public static void Encrypt(Stream input, Stream output, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        using var stream = EncryptReader(input, recipients, options);
        stream.CopyTo(output);
    }

    /// <summary>Decrypts <paramref name="input" /> to <paramref name="output" />. Armored input is auto-detected on any stream.</summary>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed, or the payload is malformed or truncated.</exception>
    public static void Decrypt(Stream input, Stream output, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        using var stream = DecryptReader(input, identities, options);
        stream.CopyTo(output);
        // A lazy-creating writer must still materialize.
        output.Write(ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    ///     Encrypts <paramref name="plaintext" /> into a new byte array — the buffer-in,
    ///     buffer-out convenience for small payloads such as secrets or database fields.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        var buffer = plaintext.ToArray();
        try
        {
            using var input = new MemoryStream(buffer);
            using var output = new MemoryStream();
            Encrypt(input, output, recipients, options);
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Decrypts <paramref name="ciphertext" /> into a new byte array. Armored input is auto-detected.</summary>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC or a payload chunk failed authentication.</exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        using var input = new MemoryStream(ciphertext.ToArray());
        using var output = new MemoryStream();

        try
        {
            Decrypt(input, output, identities, options);
            return output.ToArray();
        }
        finally
        {
            // MemoryStream.Dispose does not clear its buffer.
            CryptographicOperations.ZeroMemory(output.GetBuffer());
        }
    }

    /// <summary>
    ///     Encrypts <paramref name="input" />, writing the age header to
    ///     <paramref name="headerOutput" /> and the encrypted payload to
    ///     <paramref name="payloadOutput" />. Useful when header and payload
    ///     need to live in separate locations (e.g. a metadata store and a
    ///     blob store).
    /// </summary>
    /// <remarks>
    ///     The one entry point with no options parameter, and deliberately so: ASCII armor
    ///     is a container around a whole age file, which a detached header and payload are
    ///     not, so there is nothing <see cref="AgeEncryptOptions" /> could configure here.
    ///     <see cref="DecryptDetached" /> does take options, because it parses a header.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static void EncryptDetached(Stream input, Stream headerOutput, Stream payloadOutput, IReadOnlyList<IRecipient> recipients)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));
        try
        {
            header.WriteTo(headerOutput, fileKey);

            var payloadNonce = new byte[PayloadNonceSize];
            RandomNumberGenerator.Fill(payloadNonce);
            var payloadKey = new byte[PayloadKeySize];
            CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);

            using var payloadStream = new EncryptStream([], payloadNonce, payloadKey, input);
            payloadStream.CopyTo(payloadOutput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    ///     Decrypts an age file whose header and payload are stored separately —
    ///     the inverse of <see cref="EncryptDetached" />.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        var fileKey = UnwrapFileKey(headerInput, Materialize(identities, nameof(identities), "identity"), options ?? AgeDecryptOptions.Default);
        try
        {
            var payloadNonce = new byte[PayloadNonceSize];
            var total = 0;

            while (total < PayloadNonceSize)
            {
                var read = payloadInput.Read(payloadNonce.AsSpan(total));
                if (read == 0)
                    break;

                total += read;
            }

            if (total != PayloadNonceSize)
                throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {total} bytes");

            var payloadKey = new byte[PayloadKeySize];
            CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);

            using var decryptStream = new DecryptStream(payloadKey, payloadInput, false);
            decryptStream.CopyTo(output);
            // A lazy-creating writer must still materialize.
            output.Write(ReadOnlySpan<byte>.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    ///     Returns a readable <see cref="Stream" /> that produces age ciphertext
    ///     as the caller reads from it. Header setup and key derivation happen
    ///     eagerly; payload encryption is lazy (chunk-by-chunk on <c>Read()</c>).
    ///     Dispose the returned stream when done.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static Stream EncryptReader(Stream plaintext, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        var recipientArray = Materialize(recipients, nameof(recipients), "recipient");

        if (options?.Armor == true)
        {
            var ciphertextStream = EncryptReader(plaintext, recipientArray);
            return new ArmorStream(ciphertextStream);
        }

        var (header, fileKey) = BuildHeaderAndFileKey(recipientArray);

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = new byte[PayloadKeySize];
            CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);
        CryptographicOperations.ZeroMemory(fileKey);

        return new EncryptStream(headerBytes, payloadNonce, payloadKey, plaintext);
    }

    /// <summary>
    ///     Returns a writable <see cref="Stream" /> that encrypts the plaintext written
    ///     to it and forwards age ciphertext to <paramref name="destination" />
    ///     (<see cref="System.IO.Compression.GZipStream" />-style push encryption).
    ///     Recipient wrapping and the label/scrypt checks run eagerly; the header write
    ///     is deferred to the first write (or to <c>Dispose</c> when nothing is written,
    ///     which produces a valid empty-plaintext file). Disposing the returned stream
    ///     finalizes the age payload; <paramref name="destination" /> is never disposed.
    /// </summary>
    /// <remarks>
    ///     <c>Flush</c> flushes <paramref name="destination" /> but cannot flush a partial
    ///     age chunk: STREAM chunks are fixed size, and a short one marks the end of the
    ///     file. Plaintext written since the last 64 KiB boundary therefore stays buffered
    ///     until the stream is disposed, however often you flush. Code driving a framed or
    ///     interactive protocol should not expect <c>Flush</c> to make bytes readable
    ///     downstream.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static Stream EncryptWriter(Stream destination, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = new byte[PayloadKeySize];
            CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);
        CryptographicOperations.ZeroMemory(fileKey);

        var armor = options?.Armor == true;
        var inner = armor ? new ArmorWriterStream(destination) : destination;
        return new EncryptWriterStream(headerBytes, payloadNonce, payloadKey, inner, armor);
    }

    /// <summary>
    ///     Returns a readable plaintext <see cref="Stream" /> over an age-encrypted
    ///     <paramref name="source" />. Header parsing and MAC verification happen
    ///     eagerly; payload decryption is lazy. Armored input is auto-detected on any
    ///     stream, seekable or not. Dispose the returned stream when done.
    /// </summary>
    /// <remarks>
    ///     <see cref="Stream.CanSeek" /> mirrors the source: a seekable source yields a
    ///     seekable stream whose <see cref="Stream.Length" /> is the plaintext length
    ///     and whose <see cref="Stream.Seek" /> maps to the containing 64 KiB chunk,
    ///     with the last-read chunk cached; a non-seekable source yields a forward-only
    ///     stream. An ASCII-armored source seeks as well: armor has fixed geometry (48
    ///     bytes per 64-column line, only the last line short), so an offset translates
    ///     arithmetically and the layout is resolved from two small probes rather than
    ///     a scan.
    ///     Opening a seekable source decrypts the final chunk to authenticate the
    ///     plaintext length, so <see cref="Stream.Length" /> is trustworthy and a
    ///     truncated payload is rejected here rather than on reaching the missing tail.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header (or armor) is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">
    ///     The header MAC failed, or a seekable source's payload is truncated or
    ///     structurally impossible.
    /// </exception>
    public static Stream DecryptReader(Stream source, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        var identityArray = Materialize(identities, nameof(identities), "identity");
        options ??= AgeDecryptOptions.Default;

        var (binaryInput, needsDispose) = DeArmorIfNeeded(source, options);
        byte[]? payloadKey = null;

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identityArray, options);

            try
            {
                var payloadNonce = ReadPayloadNonce(reader);
                payloadKey = new byte[PayloadKeySize];
                CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", payloadKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fileKey);
            }

            return binaryInput.CanSeek
                ? SeekableDecryptStream.Create(payloadKey, binaryInput, binaryInput.Position, needsDispose)
                : new DecryptStream(payloadKey, binaryInput, needsDispose);
        }
        catch
        {
            if (payloadKey is not null) CryptographicOperations.ZeroMemory(payloadKey);
            if (needsDispose) binaryInput.Dispose();
            throw;
        }
    }

    /// <summary>
    ///     Returns a writable <see cref="Stream" /> that decrypts the age ciphertext
    ///     written to it and forwards plaintext to <paramref name="destination" /> — the
    ///     push counterpart of <see cref="DecryptReader" />,
    ///     for when something else drives the transfer and hands you bytes.
    ///     Disposing the returned stream finalizes decryption;
    ///     <paramref name="destination" /> is never disposed.
    /// </summary>
    /// <remarks>
    ///     Setup is necessarily lazy: nothing about the file is known until enough bytes
    ///     have been written. A header that no identity matches therefore throws from the
    ///     <c>Write</c> that completes the header, not from this call — the one place the
    ///     streaming grid is not symmetric, because the other three learn their key up
    ///     front. Armored input is auto-detected here as everywhere else.
    ///     <para>
    ///         Dispose is not optional: the final STREAM chunk is only recognisable as final
    ///         once the input ends, so a stream that is never disposed has neither
    ///         authenticated the last chunk nor detected a truncated file.
    ///     </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    public static Stream DecryptWriter(Stream destination, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null) =>
        new DecryptWriterStream(destination, Materialize(identities, nameof(identities), "identity"), options ?? AgeDecryptOptions.Default);

    /// <summary>
    ///     Parses the header of an age file without decrypting it (and without
    ///     verifying the header MAC, which requires an identity). Armored input is
    ///     auto-detected on any stream, seekable or not.
    /// </summary>
    /// <remarks>
    ///     The result is <b>unverified</b>. Because no MAC check has happened, stanza
    ///     types, argument counts, and argument contents are all attacker-controlled.
    ///     Treat them as untrusted input — in particular, a stanza may have zero
    ///     arguments, so indexing <see cref="Stanza.Args" /> without checking will throw
    ///     on a hostile file.
    /// </remarks>
    public static AgeHeader ReadHeader(Stream source, AgeDecryptOptions? options = null) =>
        AgeHeader.Parse(source, options ?? AgeDecryptOptions.Default);
}
