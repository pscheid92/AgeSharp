using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// Top-level entry point for encrypting and decrypting data in the age format.
/// All streaming APIs are memory-bounded: a 1 GiB input uses the same working
/// set as a 1 MB input (two 64 KiB chunk buffers rented from <c>ArrayPool</c>).
/// </summary>
public static partial class Age
{
    private const int FileKeySize = 16;
    internal const int PayloadNonceSize = 16;
    internal const int PayloadKeySize = 32;

    /// <summary>
    /// Encrypts <paramref name="input"/> into binary age format and writes the
    /// result to <paramref name="output"/>.
    /// </summary>
    /// <param name="input">The plaintext source. Read once, start to end.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="recipients">One or more recipients. Must all produce the same label set (see <see cref="IRecipientWithLabels"/>).</param>
    /// <exception cref="ArgumentException">No recipients were supplied.</exception>
    /// <exception cref="AgeException">
    /// Recipients have mismatched security labels, or a passphrase (scrypt)
    /// recipient was combined with other recipients.
    /// </exception>
    public static void Encrypt(Stream input, Stream output, params ReadOnlySpan<IRecipient> recipients)
        => Encrypt(input, output, AgeOptions.Default, recipients);

    /// <summary>
    /// Encrypts <paramref name="input"/> and writes the result to <paramref name="output"/>,
    /// applying <paramref name="options"/> (e.g. ASCII armor).
    /// </summary>
    /// <param name="input">The plaintext source.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="options">Encryption options; <see cref="AgeOptions.Armor"/> selects armored output.</param>
    /// <param name="recipients">One or more recipients. Must all produce the same label set (see <see cref="IRecipientWithLabels"/>).</param>
    public static void Encrypt(Stream input, Stream output, AgeOptions options, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        using var stream = EncryptReader(input, options, recipients);
        stream.CopyTo(output);
    }

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>.
    /// Armored input is auto-detected when the stream is seekable.
    /// </summary>
    /// <param name="input">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentException">No identities were supplied.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed verification.</exception>
    /// <exception cref="AgeFormatException">The input is armored and the armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The payload is malformed, truncated, or authentication failed.</exception>
    public static void Decrypt(Stream input, Stream output, params ReadOnlySpan<IIdentity> identities)
        => Decrypt(input, output, AgeOptions.Default, identities);

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>,
    /// applying <paramref name="options"/> (the header-size limits).
    /// </summary>
    public static void Decrypt(Stream input, Stream output, AgeOptions options, params ReadOnlySpan<IIdentity> identities)
    {
        using var stream = OpenRead(input, options, identities);
        stream.CopyTo(output);
        // Ensure output is touched even when plaintext is empty — matters for
        // lazy-creating writers that only materialize on first Write.
        output.Write(ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Encrypts <paramref name="input"/>, writing the age header to
    /// <paramref name="headerOutput"/> and the encrypted payload to
    /// <paramref name="payloadOutput"/>. Useful when header and payload
    /// need to live in separate locations (e.g. a metadata store and a
    /// blob store).
    /// </summary>
    public static void EncryptDetached(Stream input, Stream headerOutput, Stream payloadOutput, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        var (header, fileKey) = BuildHeaderAndFileKey(recipients);
        try
        {
            header.WriteTo(headerOutput, fileKey);

            var payloadNonce = new byte[PayloadNonceSize];
            RandomNumberGenerator.Fill(payloadNonce);
            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);

            using var payloadStream = new EncryptStream([], payloadNonce, payloadKey, input);
            payloadStream.CopyTo(payloadOutput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    /// Decrypts an age file whose header and payload are stored separately
    /// (the inverse of <see cref="EncryptDetached"/>).
    /// </summary>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, params ReadOnlySpan<IIdentity> identities)
    {
        if (identities.Length == 0)
            throw new ArgumentException("at least one identity is required", nameof(identities));

        var fileKey = UnwrapFileKey(headerInput, identities);
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

            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);

            using var decryptStream = new DecryptStream(payloadKey, payloadInput, ownsStream: false);
            decryptStream.CopyTo(output);
            // Ensure output is touched even when plaintext is empty — matters for
            // lazy-creating writers that only materialize on first Write.
            output.Write(ReadOnlySpan<byte>.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that produces age ciphertext
    /// as the caller reads from it. Header setup and key derivation happen
    /// eagerly; payload encryption is lazy (chunk-by-chunk on <c>Read()</c>).
    /// Dispose the returned stream when done.
    /// </summary>
    /// <param name="plaintext">The plaintext source.</param>
    /// <param name="recipients">One or more recipients.</param>
    public static Stream EncryptReader(Stream plaintext, params ReadOnlySpan<IRecipient> recipients)
        => EncryptReader(plaintext, AgeOptions.Default, recipients);

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that produces age ciphertext,
    /// optionally ASCII-armored per <paramref name="options"/>, as the caller reads from it.
    /// </summary>
    public static Stream EncryptReader(Stream plaintext, AgeOptions options, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        if (options.Armor)
        {
            var ciphertextStream = EncryptReader(plaintext, AgeOptions.Default, recipients);
            return new ArmorStream(ciphertextStream);
        }

        var (header, fileKey) = BuildHeaderAndFileKey(recipients);

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        CryptographicOperations.ZeroMemory(fileKey);

        return new EncryptStream(headerBytes, payloadNonce, payloadKey, plaintext);
    }

    /// <summary>
    /// Returns a writable <see cref="Stream"/> that encrypts the plaintext written
    /// to it and forwards age ciphertext to <paramref name="destination"/>
    /// (<see cref="System.IO.Compression.GZipStream"/>-style push encryption).
    /// Recipient wrapping and the label/scrypt checks run eagerly; the header write
    /// is deferred to the first write (or to <c>Dispose</c> when nothing is written,
    /// which produces a valid empty-plaintext file). Disposing the returned stream
    /// finalizes the age payload; <paramref name="destination"/> is never disposed.
    /// </summary>
    /// <param name="destination">The ciphertext destination. Left open when the returned stream is disposed.</param>
    /// <param name="recipients">One or more recipients.</param>
    /// <exception cref="ArgumentException">No recipients were supplied.</exception>
    public static Stream OpenWrite(Stream destination, params ReadOnlySpan<IRecipient> recipients)
        => OpenWrite(destination, AgeOptions.Default, recipients);

    /// <summary>
    /// Returns a writable <see cref="Stream"/> that encrypts the plaintext written
    /// to it and forwards age ciphertext — optionally ASCII-armored per
    /// <paramref name="options"/> — to <paramref name="destination"/>.
    /// See <see cref="OpenWrite(Stream, ReadOnlySpan{IRecipient})"/> for the
    /// lifecycle and stream-ownership contract.
    /// </summary>
    public static Stream OpenWrite(Stream destination, AgeOptions options, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        var (header, fileKey) = BuildHeaderAndFileKey(recipients);

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        CryptographicOperations.ZeroMemory(fileKey);

        // When armoring, ciphertext flows through a push-side armor writer that
        // wraps the caller's destination. The encrypt writer owns (and disposes,
        // to emit the footer) that wrapper but never the caller's destination.
        var inner = options.Armor ? new ArmorWriterStream(destination) : destination;
        return new EncryptWriterStream(headerBytes, payloadNonce, payloadKey, inner, ownsDestination: options.Armor);
    }

    /// <summary>
    /// Returns a readable plaintext <see cref="Stream"/> over an age-encrypted
    /// <paramref name="source"/>. Header parsing and MAC verification happen
    /// eagerly; payload decryption is lazy. Armored input is auto-detected when
    /// the source is seekable. Dispose the returned stream when done.
    /// </summary>
    /// <remarks>
    /// <see cref="Stream.CanSeek"/> mirrors the source: a seekable source yields a
    /// seekable stream whose <see cref="Stream.Length"/> is the plaintext length
    /// and whose <see cref="Stream.Seek"/> maps to the containing 64 KiB chunk,
    /// with the last-read chunk cached; a non-seekable source yields a forward-only
    /// stream. A seekable armored source is materialized (its dearmored bytes are
    /// buffered in memory) so it can seek. Payload truncation is only detected once
    /// a read reaches the affected chunk, so a seek-and-read that never touches the
    /// final chunk cannot observe a truncated tail.
    /// </remarks>
    /// <param name="source">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentException">No identities were supplied.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header (or armor) is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed, or a seekable source's payload is structurally impossible.</exception>
    public static Stream OpenRead(Stream source, params ReadOnlySpan<IIdentity> identities)
        => OpenRead(source, AgeOptions.Default, identities);

    /// <summary>
    /// Returns a readable plaintext <see cref="Stream"/>, applying
    /// <paramref name="options"/> (the header-size limits) while parsing.
    /// See <see cref="OpenRead(Stream, ReadOnlySpan{IIdentity})"/> for the
    /// seekability and truncation-detection contract.
    /// </summary>
    public static Stream OpenRead(Stream source, AgeOptions options, params ReadOnlySpan<IIdentity> identities)
    {
        if (identities.Length == 0)
            throw new ArgumentException("at least one identity is required", nameof(identities));

        var (binaryInput, needsDispose) = DeArmorIfNeeded(source, options);
        byte[]? payloadKey = null;

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities, options);
            var payloadNonce = ReadPayloadNonce(reader);
            payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
            CryptographicOperations.ZeroMemory(fileKey);

            // CanSeek mirrors the (possibly dearmored) source: a seekable input
            // gets random-access decryption; anything else stays forward-only.
            return binaryInput.CanSeek
                ? new SeekableDecryptStream(payloadKey, binaryInput, binaryInput.Position, needsDispose)
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
    /// Parses the header of an age file without decrypting it (and without
    /// verifying the header MAC, which requires an identity). Armored input is
    /// auto-detected when the stream is seekable.
    /// </summary>
    /// <param name="source">The age-encrypted source.</param>
    /// <param name="options">Parsing options (the header-size limits); defaults are used when null.</param>
    public static AgeHeader ReadHeader(Stream source, AgeOptions? options = null) =>
        AgeHeader.Parse(source, options);

    // Wrap a recipient and get its label set. Recipients that don't implement
    // IRecipientWithLabels are treated as having an empty set (mirrors the
    // reference implementation's wrapWithLabels helper).
    private static (Stanza stanza, IReadOnlyCollection<string> labels) WrapWithLabels(IRecipient recipient, ReadOnlySpan<byte> fileKey)
    {
        if (recipient is IRecipientWithLabels labelled)
            return labelled.WrapWithLabels(fileKey);

        return (recipient.Wrap(fileKey), []);
    }

    private static bool LabelSetsEqual(IReadOnlyCollection<string> a, IReadOnlyCollection<string> b)
    {
        if (a.Count == 0 && b.Count == 0)
            return true;

        // Set semantics: order-insensitive, duplicates collapse
        var set = new HashSet<string>(a, StringComparer.Ordinal);
        return set.SetEquals(b);
    }

    private static (Header header, byte[] fileKey) BuildHeaderAndFileKey(ReadOnlySpan<IRecipient> recipients)
    {
        var fileKey = new byte[FileKeySize];
        RandomNumberGenerator.Fill(fileKey);

        try
        {
            var header = new Header();

            // Wrap each recipient and collect its label set from the same call —
            // labels can be dynamic (a fresh random label, or plugin-provided),
            // so they must come from the wrap that produced the stanza, not a
            // separately-read property. All label sets must match, compared as
            // unordered sets (age-plugin.md: "treat them as an unordered set").
            IReadOnlyCollection<string>? firstLabels = null;

            for (var i = 0; i < recipients.Length; i++)
            {
                var (stanza, labels) = WrapWithLabels(recipients[i], fileKey);

                if (i == 0)
                    firstLabels = labels;
                else if (!LabelSetsEqual(firstLabels!, labels))
                    throw new AgeException("cannot mix recipients with different security labels");

                header.Stanzas.Add(stanza);
            }

            // A scrypt stanza must be the only stanza in the header — the same rule
            // decryption enforces. Checked post-wrap so custom recipients that emit
            // scrypt stanzas are caught too.
            if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
                throw new AgeException("a passphrase (scrypt) recipient must be the only recipient");

            return (header, fileKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fileKey);
            throw;
        }
    }

    private static byte[] UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities, AgeOptions.Default);
        return fileKey;
    }

    internal static (byte[] fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities, AgeOptions options)
    {
        var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
        var header = ParseHeader(reader);

        // Check scrypt constraint: if any stanza is scrypt, it must be the only one
        var hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeFormatException("scrypt stanza must be the only stanza in the header");

        // Try each identity against all stanzas (batch unwrap supports plugin protocol)
        byte[]? fileKey = null;
        foreach (var identity in identities)
        {
            fileKey = identity.Unwrap(header.Stanzas);
            if (fileKey is not null)
                break;
        }

        if (fileKey is null)
            throw new NoIdentityMatchException();

        if (fileKey.Length != FileKeySize)
            throw new AgeFormatException($"file key must be {FileKeySize} bytes, got {fileKey.Length}");

        header.VerifyMac(fileKey);
        return (fileKey, reader);
    }

    private static (Stream binaryInput, bool needsDispose) DeArmorIfNeeded(Stream input, AgeOptions options)
    {
        // Armor is only detectable on a seekable source. Materialize the dearmored
        // bytes into a seekable MemoryStream so the decrypt stream mirrors the
        // source's seekability (armored files therefore cost their size in memory).
        if (input.CanSeek && AsciiArmor.IsArmored(input))
        {
            using var dearmored = AsciiArmor.Dearmor(input, options.MaxArmorLineBytes);
            var buffer = new MemoryStream();
            dearmored.CopyTo(buffer);
            buffer.Position = 0;
            return (buffer, true);
        }

        return (input, false);
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var bytesRead = reader.ReadPayloadBytes(payloadNonce);

        return bytesRead == PayloadNonceSize
            ? payloadNonce
            : throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {bytesRead} bytes");
    }

    private static Header ParseHeader(HeaderReader reader)
    {
        try
        {
            return Header.Parse(reader);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"header parse error: {ex.Message}", ex);
        }
    }
}
