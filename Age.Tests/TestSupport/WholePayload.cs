using AgeSharp;
using AgeSharp.Crypto;

namespace Age.Tests;

/// <summary>
/// A STREAM payload encrypted all at once from a raw payload key, chunk by chunk over the
/// library's chunk function: how tests build payloads, broken ones included. It buffers the whole
/// payload, which the library's streams never do, so it lives here and not in the library.
/// Decrypting is left to the library's own streams.
/// </summary>
internal static class WholePayload
{
    public static void Encrypt(ReadOnlySpan<byte> payloadKey, Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var inputData = inputMs.GetBuffer().AsSpan(0, (int)inputMs.Length);

        var counter = 0L;
        var offset = 0;

        while (true)
        {
            var chunkLen = Math.Min(StreamEncryption.ChunkSize, inputData.Length - offset);
            var isFinal = offset + chunkLen >= inputData.Length;

            output.Write(EncryptChunk(payloadKey, counter, isFinal, inputData.Slice(offset, chunkLen)));

            offset += chunkLen;
            counter++;

            if (isFinal)
                return;
        }
    }

    public static byte[] EncryptChunk(ReadOnlySpan<byte> payloadKey, long counter, bool isFinal, ReadOnlySpan<byte> plaintext)
    {
        using var cipher = AeadCipher.Create(payloadKey);
        var output = new byte[plaintext.Length + StreamEncryption.TagSize];
        StreamEncryption.EncryptChunk(cipher, counter, isFinal, plaintext, output);
        return output;
    }
}
