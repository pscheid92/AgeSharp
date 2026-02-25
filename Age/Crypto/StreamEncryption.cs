using System.Buffers.Binary;

namespace Age.Crypto;

internal static class StreamEncryption
{
    internal const int ChunkSize = 64 * 1024; // 64 KiB plaintext
    internal const int TagSize = 16; // Poly1305 tag
    internal const int EncryptedChunkSize = ChunkSize + TagSize;
    private const int NonceSize = 12;

    public static void Encrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var inputData = inputMs.GetBuffer().AsSpan(0, (int)inputMs.Length);

        var counter = 0L;
        var offset = 0;

        while (true)
        {
            var remaining = inputData.Length - offset;
            var chunkLen = Math.Min(ChunkSize, remaining);
            var isFinal = offset + chunkLen >= inputData.Length;

            var plaintext = inputData.Slice(offset, chunkLen);
            var ciphertext = EncryptChunk(payloadKey, counter, isFinal, plaintext);
            output.Write(ciphertext);

            offset += chunkLen;
            counter++;

            if (isFinal)
                break;
        }
    }

    public static void Decrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var inputData = inputMs.GetBuffer().AsSpan(0, (int)inputMs.Length);

        if (inputData.Length == 0)
            throw new AgePayloadException("payload is empty (no chunks)");

        long counter = 0;
        var offset = 0;

        while (offset < inputData.Length)
        {
            var (chunkLen, isFinal) = NextChunk(inputData, offset);
            var ciphertext = inputData.Slice(offset, chunkLen);
            var plaintext = DecryptChunk(payloadKey, counter, isFinal, ciphertext);

            if (isFinal && plaintext.Length == 0 && counter > 0)
                throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");

            output.Write(plaintext);
            offset += chunkLen;
            counter++;

            if (!isFinal)
                continue;

            if (offset < inputData.Length)
                throw new AgePayloadException("data found after final chunk");

            return;
        }

        throw new AgePayloadException("payload ended without a final chunk");
    }

    private static (int ChunkLen, bool IsFinal) NextChunk(ReadOnlySpan<byte> data, int offset)
    {
        var remaining = data.Length - offset;

        var isFinal = remaining <= EncryptedChunkSize;
        var chunkLen = isFinal ? remaining : EncryptedChunkSize;

        return chunkLen >= TagSize
            ? (chunkLen, isFinal)
            : throw new AgePayloadException("chunk too small for authentication tag");
    }

    internal static byte[] EncryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal, ReadOnlySpan<byte> plaintext)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        MakeNonce(counter, isFinal, nonce);
        return CryptoHelper.ChaChaEncrypt(payloadKey, nonce, plaintext);
    }

    internal static byte[] DecryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal, ReadOnlySpan<byte> ciphertext)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];

        MakeNonce(counter, isFinal, nonce);

        var plaintext = CryptoHelper.ChaChaDecrypt(payloadKey, nonce, ciphertext);
        return plaintext ?? throw new AgePayloadException($"chunk {counter} authentication failed (final={isFinal})");
    }

    private static void MakeNonce(long counter, bool isFinal, Span<byte> nonce)
    {
        // 12-byte nonce: 11 bytes big-endian counter + 1 byte final flag
        nonce.Clear();
        BinaryPrimitives.WriteInt64BigEndian(nonce[3..], counter);
        nonce[11] = isFinal ? (byte)1 : (byte)0;
    }
}