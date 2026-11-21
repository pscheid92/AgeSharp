using System.Buffers.Binary;

namespace AgeSharp.Crypto;

internal static class StreamEncryption
{
    internal const int ChunkSize = 64 * 1024; // 64 KiB plaintext
    internal const int TagSize = 16; // Poly1305 tag
    internal const int EncryptedChunkSize = ChunkSize + TagSize;

    /// <summary>The random nonce that starts the payload, from which its key is derived.</summary>
    internal const int PayloadNonceSize = 16;

    /// <summary>The payload key, derived from the file key and the payload nonce.</summary>
    internal const int PayloadKeySize = 32;
    private const int NonceSize = 12;

    internal static void EncryptChunk(IAeadCipher cipher, long counter, bool isFinal,
                                       ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);
        CryptoHelper.ChaChaEncrypt(cipher, nonce, plaintext, ciphertextWithTag);
    }

    internal static void DecryptChunk(IAeadCipher cipher, long counter, bool isFinal,
                                       ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);

        if (!CryptoHelper.ChaChaDecrypt(cipher, nonce, ciphertext, plaintext))
            throw new AgeAuthenticationException($"chunk {counter} authentication failed (final={isFinal})");
    }

    private static void MakeNonce(long counter, bool isFinal, Span<byte> nonce)
    {
        // 12-byte nonce: 11 bytes big-endian counter + 1 byte final flag
        nonce.Clear();
        BinaryPrimitives.WriteInt64BigEndian(nonce[3..], counter);
        nonce[11] = isFinal ? (byte)1 : (byte)0;
    }
}