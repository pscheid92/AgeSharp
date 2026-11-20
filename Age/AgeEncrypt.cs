using System.Security.Cryptography;
using AgeSharp.Crypto;
using AgeSharp;

namespace AgeSharp;

/// <summary>
/// Decrypting data in the age format; encrypting is on <see cref="Recipients"/>.
/// All streaming APIs are memory-bounded: a 1 GiB input uses the same working
/// set as a 1 MB input (two 64 KiB chunk buffers rented from <c>ArrayPool</c>).
/// </summary>
public static class AgeEncrypt
{
    internal const int PayloadNonceSize = 16;
    internal const int PayloadKeySize = 32;

    /// <summary>
    /// Decrypts an age-encrypted <paramref name="input"/> into <paramref name="output"/>.
    /// Armored input is detected, on any readable stream.
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
    /// Decrypts an age file whose header and payload are stored separately
    /// (the inverse of <see cref="Recipients.EncryptDetached"/>).
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
    /// Returns a readable <see cref="Stream"/> that yields plaintext as the
    /// caller reads from it. Header parsing and MAC verification happen
    /// eagerly; payload decryption is lazy. Armored input is detected, on any
    /// readable stream. Dispose the returned stream when done.
    /// </summary>
    public static Stream DecryptReader(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        ArgumentException.ThrowIfEmpty(identities, "identity");

        // The binary input is ours (a look-ahead or a dearmoring wrapper, neither of which
        // disposes the caller's stream). On success the returned DecryptStream takes it over, so
        // the catch covers failure alone.
        var (binaryInput, _) = AsciiArmor.Open(ciphertext);

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);

            using (fileKey)
            {
                var payloadNonce = ReadPayloadNonce(reader);
                var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", PayloadKeySize);

                return new DecryptStream(payloadKey, binaryInput, ownsStream: true);
            }
        }
        catch
        {
            binaryInput.Dispose();
            throw;
        }
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