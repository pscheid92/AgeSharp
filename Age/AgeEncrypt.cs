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
    /// <param name="recipients">One or more recipients. Must all share the same <see cref="IRecipient.Label"/>.</param>
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
    /// <param name="recipients">One or more recipients. Must all share the same <see cref="IRecipient.Label"/>.</param>
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

        var (binaryInput, needsDispose) = DeArmorIfNeeded(ciphertext);

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);

            using (fileKey)
            {
                var payloadNonce = ReadPayloadNonce(reader);
                var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", PayloadKeySize);

                return new DecryptStream(payloadKey, binaryInput, needsDispose);
            }
        }
        catch
        {
            if (needsDispose) binaryInput.Dispose();
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
        // Check label consistency — reject mixing PQ and non-PQ recipients
        var firstLabel = recipients[0].Label;

        for (var i = 1; i < recipients.Length; i++)
        {
            if (recipients[i].Label != firstLabel)
                throw new AgeException("cannot mix recipients with different security labels");
        }

        var header = new Header();

        // A plugin may legitimately answer one wrap-file-key with several stanzas, so ask for
        // all of them where the recipient can produce more than one. IRecipient.Wrap is
        // public, shipped API returning a single Stanza and cannot be widened.
        foreach (var recipient in recipients)
        {
            if (recipient is IMultiStanzaRecipient multi)
                header.Stanzas.AddRange(multi.WrapAll(fileKey));
            else
                header.Stanzas.Add(recipient.Wrap(fileKey));
        }

        // A scrypt stanza must be the only stanza in the header — the same rule decryption
        // enforces. Checked post-Wrap so custom recipients that emit scrypt stanzas are
        // caught too.
        if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
            throw new AgeException("a passphrase (scrypt) recipient must be the only recipient");

        return header;
    }

    private static FileKey UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities);
        return fileKey;
    }

    internal static (FileKey fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities)
    {
        var reader = new HeaderReader(binaryInput);
        var header = ParseHeader(reader);

        // Check scrypt constraint: if any stanza is scrypt, it must be the only one
        var hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeHeaderException("scrypt stanza must be the only stanza in the header");

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

        // Adopt validates the length and takes ownership, so from here a throw disposes rather
        // than abandons. VerifyMac failing is routine — a tampered or corrupted header.
        var owned = FileKey.Adopt(fileKey);

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

    private static (Stream binaryInput, bool needsDispose) DeArmorIfNeeded(Stream input)
    {
        if (input.CanSeek && AsciiArmor.IsArmored(input))
            return (AsciiArmor.Dearmor(input), true);

        return (input, false);
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
