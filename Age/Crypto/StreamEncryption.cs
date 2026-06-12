using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Age.Crypto;

internal static class StreamEncryption
{
    internal const int ChunkSize = 64 * 1024; // 64 KiB plaintext
    internal const int TagSize = 16; // Poly1305 tag
    internal const int EncryptedChunkSize = ChunkSize + TagSize;
    private const int NonceSize = 12;

    // Whole-stream convenience wrappers over the chunk format. These route
    // through EncryptStream/DecryptStream so they share the memory-bounded
    // production path (no full-input buffering) and stay byte-for-byte
    // identical to it. The input here carries no header/nonce preamble — just
    // the raw STREAM chunks — so an empty preamble is passed.
    public static void Encrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var stream = new EncryptStream([], [], payloadKey.ToArray(), input);
        stream.CopyTo(output);
    }

    public static void Decrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var stream = new DecryptStream(payloadKey.ToArray(), input, ownsStream: false);
        stream.CopyTo(output);
    }

    internal static void EncryptChunk(ChaCha20Poly1305 cipher, long counter, bool isFinal,
                                       ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);
        CryptoHelper.ChaChaEncrypt(cipher, nonce, plaintext, ciphertextWithTag);
    }

    internal static void EncryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal,
                                       ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);
        CryptoHelper.ChaChaEncrypt(payloadKey, nonce, plaintext, ciphertextWithTag);
    }

    internal static byte[] EncryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal, ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + TagSize];
        EncryptChunk(payloadKey, counter, isFinal, plaintext, output);
        return output;
    }

    internal static void DecryptChunk(ChaCha20Poly1305 cipher, long counter, bool isFinal,
                                       ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);

        if (!CryptoHelper.ChaChaDecrypt(cipher, nonce, ciphertext, plaintext))
            throw new AgePayloadException($"chunk {counter} authentication failed (final={isFinal})");
    }

    internal static void DecryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal,
                                       ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);

        if (!CryptoHelper.ChaChaDecrypt(payloadKey, nonce, ciphertext, plaintext))
            throw new AgePayloadException($"chunk {counter} authentication failed (final={isFinal})");
    }

    internal static byte[] DecryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < TagSize)
            throw new AgePayloadException($"chunk {counter} authentication failed (final={isFinal})");

        var plaintext = new byte[ciphertext.Length - TagSize];
        DecryptChunk(payloadKey, counter, isFinal, ciphertext, plaintext);
        return plaintext;
    }

    private static void MakeNonce(long counter, bool isFinal, Span<byte> nonce)
    {
        // 12-byte nonce: 11 bytes big-endian counter + 1 byte final flag
        nonce.Clear();
        BinaryPrimitives.WriteInt64BigEndian(nonce[3..], counter);
        nonce[11] = isFinal ? (byte)1 : (byte)0;
    }
}