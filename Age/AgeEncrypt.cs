using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Age.Recipients;

namespace Age;

/// <summary>
/// Top-level entry point for encrypting and decrypting data in the age format.
/// All streaming APIs are memory-bounded: a 1 GiB input uses the same working
/// set as a 1 MB input (two 64 KiB chunk buffers rented from <c>ArrayPool</c>).
/// </summary>
public static class AgeEncrypt
{
    internal const int PayloadNonceSize = 16;
    internal const int PayloadKeySize = 32;

    /// <summary>
    /// Encrypts <paramref name="input"/> into binary age format and writes the
    /// result to <paramref name="output"/>.
    /// </summary>
    /// <param name="input">The plaintext source. Read once, start to end.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="recipients">One or more recipients. Must all carry the same security labels (see <see cref="IRecipientWithLabels"/>).</param>
    /// <exception cref="ArgumentException">No recipients were supplied.</exception>
    /// <exception cref="AgeException">
    /// Recipients have mismatched security labels, or a passphrase (scrypt)
    /// recipient was combined with other recipients.
    /// </exception>
    public static void Encrypt(Stream input, Stream output, params ReadOnlySpan<IRecipient> recipients)
        => Encrypt(input, output, false, recipients);

    /// <summary>
    /// Encrypts <paramref name="input"/> and writes the result to <paramref name="output"/>,
    /// optionally wrapping the binary ciphertext in ASCII armor.
    /// </summary>
    /// <param name="input">The plaintext source.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="armor">If <c>true</c>, output is a PEM-like armored text block; otherwise raw binary.</param>
    /// <param name="recipients">One or more recipients. Must all carry the same security labels (see <see cref="IRecipientWithLabels"/>).</param>
    public static void Encrypt(Stream input, Stream output, bool armor, params ReadOnlySpan<IRecipient> recipients)
    {
        ArgumentException.ThrowIfEmpty(recipients, "recipient");
        using var stream = EncryptReader(input, armor, recipients);
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
    /// <exception cref="AgeHeaderException">The header is malformed.</exception>
    /// <exception cref="AgeHmacException">The header MAC failed verification.</exception>
    /// <exception cref="AgeArmorException">The input is armored and the armor is malformed.</exception>
    /// <exception cref="AgePayloadException">The payload is malformed, truncated, or authentication failed.</exception>
    public static void Decrypt(Stream input, Stream output, params ReadOnlySpan<IIdentity> identities)
    {
        using var stream = DecryptReader(input, identities);
        stream.CopyTo(output);
        output.EnsureMaterialized();
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
        ArgumentException.ThrowIfEmpty(recipients, "recipient");

        using var fileKey = FileKey.Fresh();

        var header = BuildHeader(recipients, fileKey.Bytes);
        header.WriteTo(headerOutput, fileKey.Bytes);

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", PayloadKeySize);

        using var payloadStream = new EncryptStream([], payloadNonce, payloadKey, input);
        payloadStream.CopyTo(payloadOutput);
    }

    /// <summary>
    /// Decrypts an age file whose header and payload are stored separately
    /// (the inverse of <see cref="EncryptDetached"/>).
    /// </summary>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, params ReadOnlySpan<IIdentity> identities)
    {
        ArgumentException.ThrowIfEmpty(identities, "identity");

        using var fileKey = UnwrapFileKey(headerInput, identities);

        var payloadNonce = new byte[PayloadNonceSize];
        var total = payloadInput.ReadAtLeast(payloadNonce, PayloadNonceSize, throwOnEndOfStream: false);
        if (total != PayloadNonceSize)
            throw new AgeHeaderException($"expected {PayloadNonceSize}-byte payload nonce, got {total} bytes");

        var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", PayloadKeySize);

        using var decryptStream = new DecryptStream(payloadKey, payloadInput, ownsStream: false);
        decryptStream.CopyTo(output);
        output.EnsureMaterialized();
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
        => EncryptReader(plaintext, false, recipients);

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that produces age ciphertext,
    /// optionally ASCII-armored, as the caller reads from it.
    /// </summary>
    public static Stream EncryptReader(Stream plaintext, bool armor, params ReadOnlySpan<IRecipient> recipients)
    {
        ArgumentException.ThrowIfEmpty(recipients, "recipient");

        if (armor)
        {
            var ciphertextStream = EncryptReader(plaintext, armor: false, recipients);
            return new ArmorStream(ciphertextStream);
        }

        using var fileKey = FileKey.Fresh();

        var header = BuildHeader(recipients, fileKey.Bytes);

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey.Bytes);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", PayloadKeySize);

        return new EncryptStream(headerBytes, payloadNonce, payloadKey, plaintext);
    }

    /// <summary>
    /// Returns a readable <see cref="Stream"/> that yields plaintext as the
    /// caller reads from it. Header parsing and MAC verification happen
    /// eagerly; payload decryption is lazy. Armored input is auto-detected
    /// when the stream is seekable. Dispose the returned stream when done.
    /// </summary>
    public static Stream DecryptReader(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        ArgumentException.ThrowIfEmpty(identities, "identity");

        // `dearmored` is the ownership token: non-null means we made it and must dispose it.
        // Unlike the other two dearmor sites this one cannot use `using`, because on success
        // ownership passes to the returned DecryptStream — so the catch covers failure alone.
        var dearmored = ciphertext.CanSeek && AsciiArmor.IsArmored(ciphertext)
            ? AsciiArmor.Dearmor(ciphertext)
            : null;

        try
        {
            var binaryInput = dearmored ?? ciphertext;
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);

            using (fileKey)
            {
                var payloadNonce = ReadPayloadNonce(reader);
                var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", PayloadKeySize);

                return new DecryptStream(payloadKey, binaryInput, ownsStream: dearmored is not null);
            }
        }
        catch
        {
            dearmored?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Wraps <paramref name="fileKey"/> for every recipient and returns the resulting header.
    /// </summary>
    /// <remarks>
    /// Takes the file key rather than creating one, so that whoever created it also holds the
    /// only <c>finally</c> that clears it. When this returned the key as well, a caller reading
    /// its own method could not tell whether a throw in here leaked — the guarantee lived in
    /// another method's <c>catch</c>. That non-locality is how S9 happened: all five sites the
    /// survey found were "the clear is somewhere else" situations. Nothing here owns the key, so
    /// nothing here has to remember to clear it.
    /// </remarks>
    private static Header BuildHeader(ReadOnlySpan<IRecipient> recipients, ReadOnlySpan<byte> fileKey)
    {
        var header = new Header();
        HashSet<string>? firstLabels = null;

        foreach (var recipient in recipients)
        {
            var (stanzas, labels) = recipient is IRecipientWithLabels labelled
                ? labelled.WrapWithLabels(fileKey)
                : new LabelledStanzas(recipient.Wrap(fileKey), []);

            // A header without this recipient's stanza would leave out a recipient the caller
            // named, which is not something to do silently. Null (a default LabelledStanzas, or
            // a custom Wrap returning null) is the same mistake.
            if (stanzas is null || stanzas.Count == 0)
                throw new AgeException($"recipient {recipient.GetType().Name} produced no stanzas");

            // age-plugin.md:227: every stanza wrapping one file key must carry exactly the same
            // label set. Agreeing with the first recipient's set implies agreeing pairwise. The
            // comparison is ordinal whatever set type the recipient handed over.
            var labelSet = new HashSet<string>(labels ?? [], StringComparer.Ordinal);

            if (firstLabels is null)
                firstLabels = labelSet;
            else if (!firstLabels.SetEquals(labelSet))
                throw new AgeException(IncompatibleLabels(firstLabels, labelSet));

            header.Stanzas.AddRange(stanzas);
        }

        // A scrypt stanza must be the only stanza in the header — the same rule decryption
        // enforces. Checked post-Wrap so custom recipients that emit scrypt stanzas are
        // caught too.
        if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
            throw new AgeException("a passphrase (scrypt) recipient must be the only recipient");

        return header;
    }

    /// <summary>
    /// Explains a label mismatch, naming the consequence when post-quantum security is what was
    /// lost. "Different security labels" is accurate but leaves the user to work out the cost.
    /// </summary>
    private static string IncompatibleLabels(HashSet<string> a, HashSet<string> b)
    {
        const string postQuantum = "postquantum";

        if (a.Contains(postQuantum) != b.Contains(postQuantum))
            return "cannot mix post-quantum and classical recipients: the file would be "
                 + "readable by a quantum computer, so the post-quantum recipient buys nothing";

        return $"cannot mix recipients with different security labels: {Describe(a)} and {Describe(b)}";

        static string Describe(HashSet<string> labels) =>
            labels.Count == 0 ? "none" : string.Join(", ", labels.Order(StringComparer.Ordinal).Select(l => $"\"{l}\""));
    }

    private static FileKey UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities);
        return fileKey;
    }

    /// <summary>
    /// The identities in the order they are tried: the library's own (X25519, ML-KEM-768-X25519,
    /// scrypt) first, then the rest, each group in the order given. As in go-age (age.go,
    /// decryptHdr): an SSH key or a plugin may ask the user for a passphrase or a touch, and
    /// should not when one of these already opens the file. The caller's identities are copied,
    /// not rearranged.
    /// </summary>
    private static IIdentity[] NativeFirst(ReadOnlySpan<IIdentity> identities)
    {
        var ordered = new IIdentity[identities.Length];
        var next = 0;

        foreach (var identity in identities)
        {
            if (IsNative(identity))
                ordered[next++] = identity;
        }

        foreach (var identity in identities)
        {
            if (!IsNative(identity))
                ordered[next++] = identity;
        }

        return ordered;

        static bool IsNative(IIdentity identity) =>
            identity is X25519Identity or MlKem768X25519Identity or ScryptRecipient;
    }

    internal static (FileKey fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities)
    {
        var reader = new HeaderReader(binaryInput);
        var header = ParseHeader(reader);

        var hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeHeaderException("scrypt stanza must be the only stanza in the header");

        var owned = FileKey.UnwrapFrom(header.Stanzas, NativeFirst(identities))
                    ?? throw new NoIdentityMatchException();

        // From here a throw disposes the key rather than abandons it. VerifyMac failing is
        // routine: a tampered or corrupted header.

        try
        {
            header.VerifyMac(owned.Bytes);
            return (owned, reader);
        }
        catch
        {
            owned.Dispose();
            throw;
        }
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var bytesRead = reader.ReadPayloadBytes(payloadNonce);

        return bytesRead == PayloadNonceSize
            ? payloadNonce
            : throw new AgeHeaderException($"expected {PayloadNonceSize}-byte payload nonce, got {bytesRead} bytes");
    }

    private static Header ParseHeader(HeaderReader reader)
    {
        try
        {
            return Header.Parse(reader);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"header parse error: {ex.Message}", ex);
        }
    }
}