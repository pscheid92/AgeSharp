using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// Top-level entry point for encrypting and decrypting data in the age format.
/// All streaming APIs are memory-bounded: a 1 GiB input uses the same working
/// set as a 1 MB input (two 64 KiB chunk buffers rented from <c>ArrayPool</c>).
/// This holds for ASCII-armored input too — armor is decoded a line at a time
/// rather than buffered — and on the asynchronous paths as well as the
/// synchronous ones.
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
    /// <param name="first">The first recipient. Required, so that omitting recipients entirely is a compile error.</param>
    /// <param name="rest">Any further recipients. All recipients must produce the same label set (see <see cref="IRecipientWithLabels"/>).</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is null.</exception>
    /// <exception cref="AgeException">
    /// Recipients have mismatched security labels, or a passphrase (scrypt)
    /// recipient was combined with other recipients.
    /// </exception>
    public static void Encrypt(Stream input, Stream output, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => Encrypt(input, output, AgeEncryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Encrypts <paramref name="input"/> and writes the result to <paramref name="output"/>,
    /// applying <paramref name="options"/> (e.g. ASCII armor).
    /// </summary>
    /// <param name="input">The plaintext source.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="options">Encryption options; <see cref="AgeEncryptOptions.Armor"/> selects armored output.</param>
    /// <param name="first">The first recipient.</param>
    /// <param name="rest">Any further recipients.</param>
    public static void Encrypt(Stream input, Stream output, AgeEncryptOptions options, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => Encrypt(input, output, options, Combine(first, rest));

    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> for a
    /// collection of recipients — the overload to reach for when the recipients
    /// were assembled at runtime (from a recipients file, say) rather than
    /// written out at the call site.
    /// </summary>
    /// <param name="input">The plaintext source. Read once, start to end.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="recipients">One or more recipients. Must all produce the same label set (see <see cref="IRecipientWithLabels"/>).</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients"/> is empty.</exception>
    public static void Encrypt(Stream input, Stream output, IReadOnlyList<IRecipient> recipients)
        => Encrypt(input, output, AgeEncryptOptions.Default, recipients);

    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> for a
    /// collection of recipients, applying <paramref name="options"/>.
    /// </summary>
    public static void Encrypt(Stream input, Stream output, AgeEncryptOptions options, IReadOnlyList<IRecipient> recipients)
    {
        using var stream = EncryptReader(input, options, recipients);
        stream.CopyTo(output);
    }

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>.
    /// Armored input is auto-detected on any stream, seekable or not.
    /// </summary>
    /// <param name="input">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="first">The first identity. Required, so that omitting identities entirely is a compile error.</param>
    /// <param name="rest">Any further identities. All are tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is null.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed verification.</exception>
    /// <exception cref="AgeFormatException">The input is armored and the armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The payload is malformed, truncated, or authentication failed.</exception>
    public static void Decrypt(Stream input, Stream output, IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => Decrypt(input, output, AgeDecryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>,
    /// applying <paramref name="options"/> (armor strictness and the header-size limits).
    /// </summary>
    public static void Decrypt(Stream input, Stream output, AgeDecryptOptions options, IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => Decrypt(input, output, options, Combine(first, rest));

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>
    /// using a collection of identities — the overload to reach for when the
    /// identities were loaded at runtime rather than written out at the call site.
    /// </summary>
    /// <param name="input">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities"/> is empty.</exception>
    public static void Decrypt(Stream input, Stream output, IReadOnlyList<IIdentity> identities)
        => Decrypt(input, output, AgeDecryptOptions.Default, identities);

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>
    /// using a collection of identities, applying <paramref name="options"/>.
    /// </summary>
    public static void Decrypt(Stream input, Stream output, AgeDecryptOptions options, IReadOnlyList<IIdentity> identities)
    {
        using var stream = DecryptReader(input, options, identities);
        stream.CopyTo(output);
        // Ensure output is touched even when plaintext is empty — matters for
        // lazy-creating writers that only materialize on first Write.
        output.Write(ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and returns the age ciphertext as a
    /// new byte array. A buffer-in, buffer-out convenience for small payloads
    /// (secrets, database fields) that skips the <see cref="MemoryStream"/> ceremony.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="first">The first recipient. Required, so that omitting recipients entirely is a compile error.</param>
    /// <param name="rest">Any further recipients. All must produce the same label set.</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is null.</exception>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => Encrypt(plaintext, AgeEncryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into a new byte array, applying
    /// <paramref name="options"/> (e.g. ASCII armor).
    /// </summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, AgeEncryptOptions options, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => Encrypt(plaintext, options, Combine(first, rest));

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into a new byte array for a collection
    /// of recipients.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="recipients">One or more recipients. Must all produce the same label set.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients"/> is empty.</exception>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, IReadOnlyList<IRecipient> recipients)
        => Encrypt(plaintext, AgeEncryptOptions.Default, recipients);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into a new byte array for a collection
    /// of recipients, applying <paramref name="options"/>.
    /// </summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, AgeEncryptOptions options, IReadOnlyList<IRecipient> recipients)
    {
        // Copy into an owned buffer so the plaintext can be zeroed afterwards; the
        // returned ciphertext is not secret.
        var buffer = plaintext.ToArray();
        try
        {
            using var input = new MemoryStream(buffer);
            using var output = new MemoryStream();
            Encrypt(input, output, options, recipients);
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// Decrypts age <paramref name="ciphertext"/> and returns the plaintext as a
    /// new byte array. The buffer-in, buffer-out counterpart to
    /// <see cref="Encrypt(ReadOnlySpan{byte}, IRecipient, ReadOnlySpan{IRecipient})"/>;
    /// armored input is auto-detected.
    /// </summary>
    /// <param name="ciphertext">The age ciphertext (binary or ASCII-armored).</param>
    /// <param name="first">The first identity. Required, so that omitting identities entirely is a compile error.</param>
    /// <param name="rest">Any further identities. All are tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is null.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC or a payload chunk failed authentication.</exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => Decrypt(ciphertext, AgeDecryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Decrypts age <paramref name="ciphertext"/> into a new byte array, applying
    /// <paramref name="options"/> (armor strictness and the header-size limits).
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, AgeDecryptOptions options, IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => Decrypt(ciphertext, options, Combine(first, rest));

    /// <summary>
    /// Decrypts age <paramref name="ciphertext"/> into a new byte array using a
    /// collection of identities.
    /// </summary>
    /// <param name="ciphertext">The age ciphertext (binary or ASCII-armored).</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities"/> is empty.</exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, IReadOnlyList<IIdentity> identities)
        => Decrypt(ciphertext, AgeDecryptOptions.Default, identities);

    /// <summary>
    /// Decrypts age <paramref name="ciphertext"/> into a new byte array using a
    /// collection of identities, applying <paramref name="options"/>.
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, AgeDecryptOptions options, IReadOnlyList<IIdentity> identities)
    {
        using var input = new MemoryStream(ciphertext.ToArray());
        using var output = new MemoryStream();
        Decrypt(input, output, options, identities);
        return output.ToArray();
    }

    /// <summary>
    /// Encrypts <paramref name="input"/>, writing the age header to
    /// <paramref name="headerOutput"/> and the encrypted payload to
    /// <paramref name="payloadOutput"/>. Useful when header and payload
    /// need to live in separate locations (e.g. a metadata store and a
    /// blob store).
    /// </summary>
    /// <remarks>
    /// This is the one entry point with no options overload, and deliberately so:
    /// ASCII armor is a container around a whole age file, which a detached header
    /// and payload are not, so there is nothing
    /// <see cref="AgeEncryptOptions"/> could configure here.
    /// <see cref="DecryptDetached(Stream, Stream, Stream, AgeDecryptOptions, IIdentity, ReadOnlySpan{IIdentity})"/>
    /// does take options, because it parses a header.
    /// </remarks>
    /// <param name="input">The plaintext source.</param>
    /// <param name="headerOutput">The destination for the age header.</param>
    /// <param name="payloadOutput">The destination for the encrypted payload.</param>
    /// <param name="first">The first recipient. Required, so that omitting recipients entirely is a compile error.</param>
    /// <param name="rest">Any further recipients.</param>
    public static void EncryptDetached(Stream input, Stream headerOutput, Stream payloadOutput, IRecipient first,
                                       params ReadOnlySpan<IRecipient> rest)
        => EncryptDetached(input, headerOutput, payloadOutput, Combine(first, rest));

    /// <summary>
    /// Encrypts <paramref name="input"/> to a detached header and payload for a
    /// collection of recipients.
    /// </summary>
    /// <param name="input">The plaintext source.</param>
    /// <param name="headerOutput">The destination for the age header.</param>
    /// <param name="payloadOutput">The destination for the encrypted payload.</param>
    /// <param name="recipients">One or more recipients. Must all produce the same label set.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients"/> is empty.</exception>
    public static void EncryptDetached(Stream input, Stream headerOutput, Stream payloadOutput, IReadOnlyList<IRecipient> recipients)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));
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
    /// (the inverse of <see cref="EncryptDetached(Stream, Stream, Stream, IRecipient, ReadOnlySpan{IRecipient})"/>).
    /// </summary>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, IIdentity first,
                                       params ReadOnlySpan<IIdentity> rest)
        => DecryptDetached(headerInput, payloadInput, output, AgeDecryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Decrypts an age file whose header and payload are stored separately,
    /// applying <paramref name="options"/> (the header-size limits) while parsing
    /// the detached header.
    /// </summary>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, AgeDecryptOptions options,
                                       IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => DecryptDetached(headerInput, payloadInput, output, options, Combine(first, rest));

    /// <summary>
    /// Decrypts an age file whose header and payload are stored separately, using a
    /// collection of identities.
    /// </summary>
    /// <param name="headerInput">The detached age header.</param>
    /// <param name="payloadInput">The detached encrypted payload.</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="identities">One or more identities tried against the header's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities"/> is empty.</exception>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output,
                                       IReadOnlyList<IIdentity> identities)
        => DecryptDetached(headerInput, payloadInput, output, AgeDecryptOptions.Default, identities);

    /// <summary>
    /// Decrypts an age file whose header and payload are stored separately, using a
    /// collection of identities and applying <paramref name="options"/>.
    /// </summary>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, AgeDecryptOptions options,
                                       IReadOnlyList<IIdentity> identities)
    {
        var fileKey = UnwrapFileKey(headerInput, Materialize(identities, nameof(identities), "identity"), options);
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
    /// <param name="first">The first recipient. Required, so that omitting recipients entirely is a compile error.</param>
    /// <param name="rest">Any further recipients.</param>
    public static Stream EncryptReader(Stream plaintext, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => EncryptReader(plaintext, AgeEncryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that produces age ciphertext,
    /// optionally ASCII-armored per <paramref name="options"/>, as the caller reads from it.
    /// </summary>
    public static Stream EncryptReader(Stream plaintext, AgeEncryptOptions options, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => EncryptReader(plaintext, options, Combine(first, rest));

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that produces age ciphertext for a
    /// collection of recipients as the caller reads from it.
    /// </summary>
    /// <param name="plaintext">The plaintext source.</param>
    /// <param name="recipients">One or more recipients.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients"/> is empty.</exception>
    public static Stream EncryptReader(Stream plaintext, IReadOnlyList<IRecipient> recipients)
        => EncryptReader(plaintext, AgeEncryptOptions.Default, recipients);

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that produces age ciphertext for a
    /// collection of recipients, applying <paramref name="options"/>.
    /// </summary>
    public static Stream EncryptReader(Stream plaintext, AgeEncryptOptions options, IReadOnlyList<IRecipient> recipients)
    {
        var recipientArray = Materialize(recipients, nameof(recipients), "recipient");

        if (options.Armor)
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
    /// <param name="first">The first recipient. Required, so that omitting recipients entirely is a compile error.</param>
    /// <param name="rest">Any further recipients.</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is null.</exception>
    public static Stream EncryptWriter(Stream destination, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => EncryptWriter(destination, AgeEncryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Returns a writable <see cref="Stream"/> that encrypts the plaintext written
    /// to it and forwards age ciphertext — optionally ASCII-armored per
    /// <paramref name="options"/> — to <paramref name="destination"/>.
    /// See <see cref="EncryptWriter(Stream, IRecipient, ReadOnlySpan{IRecipient})"/> for
    /// the lifecycle and stream-ownership contract.
    /// </summary>
    public static Stream EncryptWriter(Stream destination, AgeEncryptOptions options, IRecipient first, params ReadOnlySpan<IRecipient> rest)
        => EncryptWriter(destination, options, Combine(first, rest));

    /// <summary>
    /// Returns a writable <see cref="Stream"/> that encrypts plaintext written to it
    /// for a collection of recipients. See
    /// <see cref="EncryptWriter(Stream, IRecipient, ReadOnlySpan{IRecipient})"/> for the
    /// lifecycle and stream-ownership contract.
    /// </summary>
    /// <param name="destination">The ciphertext destination. Left open when the returned stream is disposed.</param>
    /// <param name="recipients">One or more recipients.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients"/> is empty.</exception>
    public static Stream EncryptWriter(Stream destination, IReadOnlyList<IRecipient> recipients)
        => EncryptWriter(destination, AgeEncryptOptions.Default, recipients);

    /// <summary>
    /// Returns a writable <see cref="Stream"/> that encrypts plaintext written to it
    /// for a collection of recipients, applying <paramref name="options"/>.
    /// </summary>
    public static Stream EncryptWriter(Stream destination, AgeEncryptOptions options, IReadOnlyList<IRecipient> recipients)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));

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
    /// eagerly; payload decryption is lazy. Armored input is auto-detected on any
    /// stream, seekable or not. Dispose the returned stream when done.
    /// </summary>
    /// <remarks>
    /// <see cref="Stream.CanSeek"/> mirrors the source: a seekable source yields a
    /// seekable stream whose <see cref="Stream.Length"/> is the plaintext length
    /// and whose <see cref="Stream.Seek"/> maps to the containing 64 KiB chunk,
    /// with the last-read chunk cached; a non-seekable source yields a forward-only
    /// stream, as does an armored one — armor is decoded a line at a time, so it
    /// gives up seeking rather than buying it with the file's size in memory.
    /// Opening a seekable source decrypts the final chunk to authenticate the
    /// plaintext length, so <see cref="Stream.Length"/> is trustworthy and a
    /// truncated payload is rejected here rather than on reaching the missing tail.
    /// </remarks>
    /// <param name="source">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="first">The first identity. Required, so that omitting identities entirely is a compile error.</param>
    /// <param name="rest">Any further identities. All are tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is null.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header (or armor) is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed, or a seekable source's payload is truncated or structurally impossible.</exception>
    public static Stream DecryptReader(Stream source, IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => DecryptReader(source, AgeDecryptOptions.Default, Combine(first, rest));

    /// <summary>
    /// Returns a readable plaintext <see cref="Stream"/>, applying
    /// <paramref name="options"/> (armor strictness and the header-size limits) while
    /// parsing. See <see cref="DecryptReader(Stream, IIdentity, ReadOnlySpan{IIdentity})"/>
    /// for the seekability and truncation-detection contract.
    /// </summary>
    public static Stream DecryptReader(Stream source, AgeDecryptOptions options, IIdentity first, params ReadOnlySpan<IIdentity> rest)
        => DecryptReader(source, options, Combine(first, rest));

    /// <summary>
    /// Returns a readable plaintext <see cref="Stream"/> over an age-encrypted
    /// <paramref name="source"/> using a collection of identities. See
    /// <see cref="DecryptReader(Stream, IIdentity, ReadOnlySpan{IIdentity})"/> for the
    /// seekability and truncation-detection contract.
    /// </summary>
    /// <param name="source">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities"/> is empty.</exception>
    public static Stream DecryptReader(Stream source, IReadOnlyList<IIdentity> identities)
        => DecryptReader(source, AgeDecryptOptions.Default, identities);

    /// <summary>
    /// Returns a readable plaintext <see cref="Stream"/> over an age-encrypted
    /// <paramref name="source"/> using a collection of identities, applying
    /// <paramref name="options"/>.
    /// </summary>
    public static Stream DecryptReader(Stream source, AgeDecryptOptions options, IReadOnlyList<IIdentity> identities)
    {
        var identityArray = Materialize(identities, nameof(identities), "identity");

        var (binaryInput, needsDispose) = DeArmorIfNeeded(source, options);
        byte[]? payloadKey = null;

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identityArray, options);
            var payloadNonce = ReadPayloadNonce(reader);
            payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
            CryptographicOperations.ZeroMemory(fileKey);

            // CanSeek mirrors the (possibly dearmored) source: a seekable input
            // gets random-access decryption; anything else stays forward-only.
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
    /// Parses the header of an age file without decrypting it (and without
    /// verifying the header MAC, which requires an identity). Armored input is
    /// auto-detected on any stream, seekable or not.
    /// </summary>
    /// <param name="source">The age-encrypted source.</param>
    public static AgeHeader ReadHeader(Stream source) =>
        ReadHeader(source, AgeDecryptOptions.Default);

    /// <summary>
    /// Parses the header of an age file without decrypting it, applying
    /// <paramref name="options"/> (the header-size limits) while parsing.
    /// </summary>
    /// <param name="source">The age-encrypted source.</param>
    /// <param name="options">Parsing options (the header-size limits).</param>
    public static AgeHeader ReadHeader(Stream source, AgeDecryptOptions options) =>
        AgeHeader.Parse(source, options);

    // Splices a `first, params rest` pair back into the single sequence the
    // implementations work over. Taking the first element as its own parameter is
    // what makes "I forgot the recipients" a compile error rather than an
    // ArgumentException at runtime; the cost is this one small array per call,
    // on a path that already allocates a header.
    private static T[] Combine<T>(T first, ReadOnlySpan<T> rest)
    {
        ArgumentNullException.ThrowIfNull(first, nameof(first));

        var all = new T[rest.Length + 1];
        all[0] = first;
        rest.CopyTo(all.AsSpan(1));
        return all;
    }

    // Validates a caller-supplied collection and hands back an array the span-based
    // internals can consume. An array passes through without copying — which is the
    // common case, since every `first, params rest` overload arrives via Combine.
    // The emptiness guard lives here, and only here: the params overloads cannot
    // produce an empty sequence, so this is the one shape that still needs checking.
    private static T[] Materialize<T>(IReadOnlyList<T> items, string paramName, string noun)
    {
        ArgumentNullException.ThrowIfNull(items, paramName);

        if (items.Count == 0)
            throw new ArgumentException($"at least one {noun} is required", paramName);

        return items as T[] ?? [.. items];
    }

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

    private static byte[] UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities, AgeDecryptOptions options)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities, options);
        return fileKey;
    }

    internal static (byte[] fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities, AgeDecryptOptions options)
    {
        var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
        var fileKey = UnwrapHeader(reader, identities);
        return (fileKey, reader);
    }

    // Parses the already-read (sync or async-prefilled) header from the reader,
    // enforces the scrypt-alone rule, unwraps the file key with the identities,
    // and verifies the header MAC. No I/O — the reader serves buffered lines, so
    // this is shared verbatim by the sync and async decrypt paths.
    internal static byte[] UnwrapHeader(HeaderReader reader, ReadOnlySpan<IIdentity> identities)
    {
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
        return fileKey;
    }

    // Detects armor by lookahead and, when present, layers a streaming dearmor over
    // the source. Armored input is therefore forward-only and costs one chunk of
    // memory rather than the file's size; binary input passes straight through with
    // its seekability intact. needsDispose refers to the wrapper only — the caller's
    // stream is never disposed.
    private static (Stream binaryInput, bool needsDispose) DeArmorIfNeeded(Stream input, AgeDecryptOptions options)
    {
        var (source, isArmored) = AsciiArmor.Detect(input, requireArmored: options.RequireArmor);

        return isArmored
            ? (AsciiArmor.Dearmor(source, options.MaxArmorLineBytes), true)
            : (source, false);
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
