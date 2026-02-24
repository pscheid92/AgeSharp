using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Age.Recipients;

namespace Age;

public sealed class AgeRandomAccess : IDisposable
{
    private const int PayloadNonceSize = 16;

    private readonly Stream _ciphertext;
    private readonly byte[] _payloadKey;
    private readonly long _payloadStart; // Position of first encrypted chunk in stream
    private readonly long _totalEncryptedPayload; // Total bytes of encrypted chunks
    private bool _disposed;

    public long PlaintextLength { get; }

    public AgeRandomAccess(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        if (!ciphertext.CanSeek)
            throw new ArgumentException("ciphertext stream must be seekable", nameof(ciphertext));

        _ciphertext = ciphertext;

        // Detect and handle ASCII armor
        Stream binaryInput;
        bool needsDispose = false;
        if (AsciiArmor.IsArmored(ciphertext))
        {
            binaryInput = AsciiArmor.Dearmor(ciphertext);
            needsDispose = true;
        }
        else
        {
            binaryInput = ciphertext;
            binaryInput.Position = 0;
        }

        try
        {
            var (fileKey, reader) = AgeEncrypt.UnwrapHeaderFromReader(binaryInput, identities);
            try
            {
                // Read 16-byte payload nonce
                var payloadNonce = new byte[PayloadNonceSize];
                int nonceRead = reader.ReadPayloadBytes(payloadNonce);
                if (nonceRead != PayloadNonceSize)
                    throw new AgeHeaderException($"expected 16-byte payload nonce, got {nonceRead} bytes");

                _payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);
                _payloadStart = binaryInput.Position;

                long totalStreamLen = binaryInput.Length;
                _totalEncryptedPayload = totalStreamLen - _payloadStart;

                if (_totalEncryptedPayload == 0)
                    throw new AgePayloadException("payload is empty (no chunks)");

                PlaintextLength = ComputePlaintextLength(_totalEncryptedPayload);

                if (needsDispose)
                {
                    // For armored input, we need to keep the dearmored MemoryStream
                    // Replace _ciphertext reference with dearmored data
                    // We can't use the original stream for seeking into binary data
                    // Store the dearmored stream for ReadAt
                    _armoredBinaryInput = (MemoryStream)binaryInput;
                    needsDispose = false; // Don't dispose, we're keeping it
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fileKey);
            }
        }
        finally
        {
            if (needsDispose) binaryInput.Dispose();
        }
    }

    private MemoryStream? _armoredBinaryInput;

    private Stream BinaryStream => _armoredBinaryInput ?? _ciphertext;

    public int ReadAt(long plaintextOffset, Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (plaintextOffset < 0 || plaintextOffset >= PlaintextLength)
        {
            if (PlaintextLength == 0 || plaintextOffset >= PlaintextLength)
                return 0;
        }

        int totalRead = 0;
        long currentOffset = plaintextOffset;

        while (totalRead < buffer.Length && currentOffset < PlaintextLength)
        {
            long chunkIndex = currentOffset / StreamEncryption.ChunkSize;
            int offsetInChunk = (int)(currentOffset % StreamEncryption.ChunkSize);

            // Compute ciphertext position for this chunk
            long ciphertextPos = _payloadStart + chunkIndex * StreamEncryption.EncryptedChunkSize;

            // Determine chunk size and if it's the final chunk
            long totalChunks = ComputeTotalChunks(_totalEncryptedPayload);
            bool isFinal = (chunkIndex == totalChunks - 1);

            int encChunkSize;
            if (isFinal)
            {
                encChunkSize = (int)(_totalEncryptedPayload - chunkIndex * StreamEncryption.EncryptedChunkSize);
            }
            else
            {
                encChunkSize = StreamEncryption.EncryptedChunkSize;
            }

            // Read the encrypted chunk
            var encChunk = new byte[encChunkSize];
            var stream = BinaryStream;
            stream.Position = ciphertextPos;
            int bytesRead = 0;
            while (bytesRead < encChunkSize)
            {
                int read = stream.Read(encChunk, bytesRead, encChunkSize - bytesRead);
                if (read == 0) break;
                bytesRead += read;
            }

            if (bytesRead != encChunkSize)
                throw new AgePayloadException($"could not read full chunk at offset {ciphertextPos}");

            // Decrypt the chunk
            var plaintext = StreamEncryption.DecryptChunk(_payloadKey, chunkIndex, isFinal, encChunk);

            // Validate empty final chunk rule
            if (isFinal && plaintext.Length == 0 && chunkIndex > 0)
                throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");

            // Copy requested portion to output
            int availableInChunk = plaintext.Length - offsetInChunk;
            int toCopy = Math.Min(availableInChunk, buffer.Length - totalRead);
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
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_payloadKey);
            _armoredBinaryInput?.Dispose();
            _disposed = true;
        }
    }

    private static long ComputePlaintextLength(long totalEncryptedPayload)
    {
        long totalChunks = ComputeTotalChunks(totalEncryptedPayload);
        long fullChunks = totalChunks - 1;
        long lastChunkEncSize = totalEncryptedPayload - fullChunks * StreamEncryption.EncryptedChunkSize;
        long lastChunkPlainSize = lastChunkEncSize - StreamEncryption.TagSize;

        if (lastChunkPlainSize < 0)
            throw new AgePayloadException("chunk too small for authentication tag");

        return fullChunks * StreamEncryption.ChunkSize + lastChunkPlainSize;
    }

    private static long ComputeTotalChunks(long totalEncryptedPayload)
    {
        // Each non-final chunk is exactly EncryptedChunkSize bytes
        // The final chunk is <= EncryptedChunkSize bytes
        if (totalEncryptedPayload <= StreamEncryption.EncryptedChunkSize)
            return 1;
        long fullChunks = totalEncryptedPayload / StreamEncryption.EncryptedChunkSize;
        long remainder = totalEncryptedPayload % StreamEncryption.EncryptedChunkSize;
        if (remainder == 0)
        {
            // The last full-sized chunk IS the final chunk
            return fullChunks;
        }
        return fullChunks + 1;
    }
}
