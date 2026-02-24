using System.Buffers.Binary;

namespace Age.Crypto;

internal static class StreamEncryption
{
    private const int ChunkSize = 64 * 1024; // 64 KiB plaintext
    private const int TagSize = 16; // Poly1305 tag
    private const int EncryptedChunkSize = ChunkSize + TagSize;
    private const int NonceSize = 12;

    public static void Encrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var inputData = inputMs.GetBuffer().AsSpan(0, (int)inputMs.Length);

        Span<byte> nonce = stackalloc byte[NonceSize];
        long counter = 0;
        int offset = 0;

        while (true)
        {
            int remaining = inputData.Length - offset;
            int chunkLen = Math.Min(ChunkSize, remaining);
            bool isFinal = (offset + chunkLen >= inputData.Length);

            var plaintext = inputData.Slice(offset, chunkLen);
            MakeNonce(counter, isFinal, nonce);

            var ciphertext = CryptoHelper.ChaChaEncrypt(payloadKey, nonce, plaintext);
            output.Write(ciphertext);

            offset += chunkLen;
            counter++;

            if (isFinal) break;
        }
    }

    public static void Decrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var inputData = inputMs.GetBuffer().AsSpan(0, (int)inputMs.Length);

        if (inputData.Length == 0)
            throw new AgePayloadException("payload is empty (no chunks)");

        Span<byte> nonce = stackalloc byte[NonceSize];
        long counter = 0;
        int offset = 0;
        bool seenFinal = false;

        while (offset < inputData.Length)
        {
            if (seenFinal)
                throw new AgePayloadException("data found after final chunk");

            int remaining = inputData.Length - offset;
            var (chunkLen, isFinal) = remaining > EncryptedChunkSize
                ? (EncryptedChunkSize, false)
                : (remaining, true);

            if (chunkLen < TagSize)
                throw new AgePayloadException("chunk too small for authentication tag");

            if (!isFinal && chunkLen != EncryptedChunkSize)
                throw new AgePayloadException("non-final chunk has wrong size");

            var ciphertext = inputData.Slice(offset, chunkLen);
            MakeNonce(counter, isFinal, nonce);

            var plaintext = CryptoHelper.ChaChaDecrypt(payloadKey, nonce, ciphertext);
            if (plaintext == null)
                throw new AgePayloadException($"chunk {counter} authentication failed (final={isFinal})");

            // The final chunk can be empty ONLY if it's the first (and only) chunk
            if (isFinal && plaintext.Length == 0 && counter > 0)
                throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");

            output.Write(plaintext);

            offset += chunkLen;
            counter++;

            if (isFinal)
                seenFinal = true;
        }

        if (!seenFinal)
            throw new AgePayloadException("payload ended without a final chunk");
    }

    private static void MakeNonce(long counter, bool isFinal, Span<byte> nonce)
    {
        // 12-byte nonce: 11 bytes big-endian counter + 1 byte final flag
        nonce.Clear();
        BinaryPrimitives.WriteInt64BigEndian(nonce[3..], counter);
        nonce[11] = isFinal ? (byte)1 : (byte)0;
    }
}
