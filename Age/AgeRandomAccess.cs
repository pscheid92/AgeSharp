using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// Random-access decryption over a seekable age ciphertext: decrypt arbitrary
/// plaintext ranges without reading the whole file. Not thread-safe — the
/// instance (and streams from <see cref="GetStream"/>) reposition the underlying
/// ciphertext stream, so use one reader per thread.
/// </summary>
/// <remarks>
/// Construction parses the header, verifies its MAC, and derives the payload key.
/// Armored input is supported by materializing the dearmored ciphertext in memory,
/// so very large armored files cost their full size in memory; binary input is
/// read in place. Truncation of the final chunk is only detectable when a read
/// actually reaches it.
/// </remarks>
public sealed class AgeRandomAccess : IDisposable
{
    private readonly byte[] _payloadKey;
    private readonly long _payloadStart; // Position of first encrypted chunk in stream
    private readonly long _totalEncryptedPayload; // Total bytes of encrypted chunks
    private readonly MemoryStream? _armoredBinaryInput;
    private bool _disposed;

    /// <summary>Total plaintext length in bytes, computed from the ciphertext layout.</summary>
    public long PlaintextLength { get; }

    /// <summary>
    /// Opens an age ciphertext for random-access decryption: parses the header,
    /// unwraps the file key with the given identities, and verifies the header MAC.
    /// The stream is rewound to position 0 first and must contain nothing but the
    /// age file. The caller retains ownership of the stream.
    /// </summary>
    /// <param name="ciphertext">Seekable age ciphertext (binary or armored).</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas.</param>
    /// <exception cref="ArgumentException">The stream is not seekable, or no identities were supplied.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed verification.</exception>
    /// <exception cref="AgeAuthenticationException">The payload is empty or structurally impossible.</exception>
    public AgeRandomAccess(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        if (!ciphertext.CanSeek)
            throw new ArgumentException("ciphertext stream must be seekable", nameof(ciphertext));

        if (identities.Length == 0)
            throw new ArgumentException("at least one identity is required", nameof(identities));

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

    /// <summary>
    /// Decrypts plaintext starting at <paramref name="plaintextOffset"/> into
    /// <paramref name="buffer"/>. Returns the number of bytes written — the full
    /// buffer unless the plaintext ends first; 0 when the offset is negative or
    /// at/past <see cref="PlaintextLength"/>. Each call decrypts the touched
    /// 64 KiB chunk(s) afresh; batch small reads or use a buffered
    /// <see cref="GetStream"/> wrapper for sequential access.
    /// </summary>
    /// <exception cref="AgeAuthenticationException">A chunk is truncated or fails authentication.</exception>
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

            CryptographicOperations.ZeroMemory(plaintext);

            totalRead += toCopy;
            currentOffset += toCopy;
        }

        return totalRead;
    }

    /// <summary>
    /// Returns a readable, seekable plaintext <see cref="Stream"/> view over this
    /// reader, starting at <paramref name="plaintextOffset"/>. The stream shares
    /// this instance's state: streams from multiple calls must not be used
    /// concurrently, and disposing this reader invalidates them.
    /// </summary>
    public Stream GetStream(long plaintextOffset = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new RandomAccessDecryptStream(this, plaintextOffset);
    }

    /// <summary>Zeroes the payload key and releases any dearmored buffer.</summary>
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
            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", AgeEncrypt.PayloadKeySize);
            var payloadStart = binaryInput.Position;
            var totalEncrypted = binaryInput.Length - payloadStart;

            if (totalEncrypted == 0)
                throw new AgeAuthenticationException("payload is empty (no chunks)");

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
            throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks");

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
            : throw new AgeAuthenticationException($"could not read full chunk at offset {ciphertextPos}");
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[AgeEncrypt.PayloadNonceSize];
        var nonceRead = reader.ReadPayloadBytes(payloadNonce);

        return nonceRead == AgeEncrypt.PayloadNonceSize
            ? payloadNonce
            : throw new AgeFormatException($"expected {AgeEncrypt.PayloadNonceSize}-byte payload nonce, got {nonceRead} bytes");
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
            throw new AgeAuthenticationException("chunk too small for authentication tag");

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