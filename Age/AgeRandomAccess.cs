using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Age.Recipients;

namespace Age;

public sealed class AgeRandomAccess : IDisposable
{
    private const int PayloadNonceSize = 16;
    private const int PayloadKeySize = 32;

    private readonly byte[] _payloadKey;
    private readonly long _payloadStart; // Position of first encrypted chunk in stream
    private readonly long _totalEncryptedPayload; // Total bytes of encrypted chunks
    private readonly MemoryStream? _armoredBinaryInput;
    private bool _disposed;

    public long PlaintextLength { get; }

    public AgeRandomAccess(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        if (!ciphertext.CanSeek)
            throw new ArgumentException("ciphertext stream must be seekable", nameof(ciphertext));

        BinaryStream = ciphertext;
        var (binaryInput, needsDispose) = DeArmorInput(ciphertext);

        try
        {
            var info = InitializeFromStream(binaryInput, identities);
            _payloadKey = info.PayloadKey;
            _payloadStart = info.PayloadStart;
            _totalEncryptedPayload = info.TotalEncrypted;
            PlaintextLength = info.PlaintextLength;

            if (!needsDispose)
                return;

            // Keep the dearmored MemoryStream for ReadAt seeking
            _armoredBinaryInput = (MemoryStream)binaryInput;
            needsDispose = false;
        }
        finally
        {
            if (needsDispose) binaryInput.Dispose();
        }
    }

    public int ReadAt(long plaintextOffset, Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (plaintextOffset < 0 || plaintextOffset >= PlaintextLength)
            return 0;

        var totalRead = 0;
        var currentOffset = plaintextOffset;

        while (totalRead < buffer.Length && currentOffset < PlaintextLength)
        {
            var plaintext = DecryptChunkAt(currentOffset, out var offsetInChunk);

            var available = plaintext.Length - offsetInChunk;
            var toCopy = Math.Min(available, buffer.Length - totalRead);
            plaintext.AsSpan(offsetInChunk, toCopy).CopyTo(buffer[totalRead..]);

            totalRead += toCopy;
            currentOffset += toCopy;
        }

        return totalRead;
    }

    public Stream GetStream(long plaintextOffset = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new RandomAccessDecryptStream(this, plaintextOffset);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        CryptographicOperations.ZeroMemory(_payloadKey);
        _armoredBinaryInput?.Dispose();
        _disposed = true;
    }

    private Stream BinaryStream =>
        _armoredBinaryInput ?? field;

    private readonly record struct PayloadInfo(
        byte[] PayloadKey, long PayloadStart, long TotalEncrypted, long PlaintextLength);

    private static PayloadInfo InitializeFromStream(Stream binaryInput, ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, reader) = AgeEncrypt.UnwrapHeaderFromReader(binaryInput, identities);

        try
        {
            var payloadNonce = ReadPayloadNonce(reader);
            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
            var payloadStart = binaryInput.Position;
            var totalEncrypted = binaryInput.Length - payloadStart;

            if (totalEncrypted == 0)
                throw new AgePayloadException("payload is empty (no chunks)");

            var plaintextLength = ComputePlaintextLength(totalEncrypted);
            return new PayloadInfo(payloadKey, payloadStart, totalEncrypted, plaintextLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    private byte[] DecryptChunkAt(long plaintextOffset, out int offsetInChunk)
    {
        var chunkIndex = plaintextOffset / StreamEncryption.ChunkSize;
        offsetInChunk = (int)(plaintextOffset % StreamEncryption.ChunkSize);

        var totalChunks = ComputeTotalChunks(_totalEncryptedPayload);
        var isFinal = chunkIndex == totalChunks - 1;
        var ciphertextPos = _payloadStart + chunkIndex * StreamEncryption.EncryptedChunkSize;
        
        var encChunkSize = isFinal
            ? (int)(_totalEncryptedPayload - chunkIndex * StreamEncryption.EncryptedChunkSize)
            : StreamEncryption.EncryptedChunkSize;

        var encChunk = ReadEncryptedChunk(ciphertextPos, encChunkSize);
        var plaintext = StreamEncryption.DecryptChunk(_payloadKey, chunkIndex, isFinal, encChunk);

        if (isFinal && plaintext.Length == 0 && chunkIndex > 0)
            throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");

        return plaintext;
    }

    private byte[] ReadEncryptedChunk(long ciphertextPos, int encChunkSize)
    {
        var encChunk = new byte[encChunkSize];
        var stream = BinaryStream;
        stream.Position = ciphertextPos;

        var bytesRead = 0;
        while (bytesRead < encChunkSize)
        {
            var read = stream.Read(encChunk, bytesRead, encChunkSize - bytesRead);
            if (read == 0)
                break;

            bytesRead += read;
        }

        return bytesRead == encChunkSize
            ? encChunk
            : throw new AgePayloadException($"could not read full chunk at offset {ciphertextPos}");
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var nonceRead = reader.ReadPayloadBytes(payloadNonce);

        return nonceRead == PayloadNonceSize
            ? payloadNonce
            : throw new AgeHeaderException($"expected {PayloadNonceSize}-byte payload nonce, got {nonceRead} bytes");
    }

    private static (Stream binaryInput, bool needsDispose) DeArmorInput(Stream ciphertext)
    {
        if (AsciiArmor.IsArmored(ciphertext))
        {
            // RandomAccess needs a seekable stream, so materialize the dearmored data.
            using var dearmored = AsciiArmor.Dearmor(ciphertext);
            var ms = new MemoryStream();
            dearmored.CopyTo(ms);
            ms.Position = 0;
            return (ms, true);
        }

        ciphertext.Position = 0;
        return (ciphertext, false);
    }

    private static long ComputePlaintextLength(long totalEncryptedPayload)
    {
        var totalChunks = ComputeTotalChunks(totalEncryptedPayload);
        var fullChunks = totalChunks - 1;
        var lastChunkEncSize = totalEncryptedPayload - fullChunks * StreamEncryption.EncryptedChunkSize;
        var lastChunkPlainSize = lastChunkEncSize - StreamEncryption.TagSize;

        if (lastChunkPlainSize < 0)
            throw new AgePayloadException("chunk too small for authentication tag");

        return fullChunks * StreamEncryption.ChunkSize + lastChunkPlainSize;
    }

    private static long ComputeTotalChunks(long totalEncryptedPayload)
    {
        if (totalEncryptedPayload <= StreamEncryption.EncryptedChunkSize)
            return 1;

        var fullChunks = totalEncryptedPayload / StreamEncryption.EncryptedChunkSize;
        var remainder = totalEncryptedPayload % StreamEncryption.EncryptedChunkSize;

        // If no remainder, the last full-sized chunk IS the final chunk
        return remainder == 0 ? fullChunks : fullChunks + 1;
    }
}