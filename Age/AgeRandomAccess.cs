using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Age.Recipients;

namespace Age;

/// <summary>
/// Random-access decryption over a seekable age ciphertext: decrypt arbitrary
/// plaintext ranges without reading the whole file. Not thread-safe — the
/// instance (and streams from <see cref="GetStream"/>) reposition the underlying
/// ciphertext stream, so use one reader per thread.
/// </summary>
/// <remarks>
/// Construction parses the header, verifies its MAC, derives the payload key, and
/// decrypts the final STREAM chunk so that <see cref="PlaintextLength"/> is an
/// authenticated value and a truncated payload is rejected up front rather than
/// only when a read happens to reach the end. Armored input is supported by
/// materializing the dearmored ciphertext in memory, so very large armored files
/// cost their full size in memory; binary input is read in place.
/// </remarks>
public sealed class AgeRandomAccess : IDisposable
{
    private readonly byte[] _payloadKey;
    private readonly long _payloadStart; // Position of first encrypted chunk in stream
    private readonly long _totalEncryptedPayload; // Total bytes of encrypted chunks
    private readonly MemoryStream? _armoredBinaryInput;
    private bool _disposed;

    /// <summary>
    /// Total plaintext length in bytes. Derived from the final STREAM chunk, which is
    /// decrypted and authenticated during construction, so this is not merely a layout
    /// guess over an unverified byte count.
    /// </summary>
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
    /// <exception cref="AgeHeaderException">The header is malformed.</exception>
    /// <exception cref="AgeHmacException">The header MAC failed verification.</exception>
    /// <exception cref="AgePayloadException">The payload is empty, structurally impossible, or its
    /// final chunk is truncated or fails authentication.</exception>
    public AgeRandomAccess(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        if (!ciphertext.CanSeek)
            throw new ArgumentException("ciphertext stream must be seekable", nameof(ciphertext));

        ArgumentException.ThrowIfEmpty(identities, "identity");

        BinaryStream = ciphertext;

        // Armored input is materialized up front because ReadAt needs to seek; the MemoryStream is
        // kept for the reader's lifetime and released by Dispose. No ownership flag: if the setup
        // below throws, the constructor throws, nothing is handed out, and the MemoryStream is
        // garbage — which is all disposing it would achieve, since that does not free its buffer.
        _armoredBinaryInput = AsciiArmor.IsArmored(ciphertext) ? Materialize(ciphertext) : null;

        if (_armoredBinaryInput is null)
            ciphertext.Position = 0;

        var info = InitializeFromStream(BinaryStream, identities);
        _payloadKey = info.PayloadKey;
        _payloadStart = info.PayloadStart;
        _totalEncryptedPayload = info.TotalEncrypted;
        PlaintextLength = info.PlaintextLength;
    }

    /// <summary>
    /// Decrypts plaintext starting at <paramref name="plaintextOffset"/> into
    /// <paramref name="buffer"/>. Returns the number of bytes written — the full
    /// buffer unless the plaintext ends first; 0 when the offset is negative or
    /// at/past <see cref="PlaintextLength"/>. Each call decrypts the touched
    /// 64 KiB chunk(s) afresh; batch small reads or use a buffered
    /// <see cref="GetStream"/> wrapper for sequential access.
    /// </summary>
    /// <exception cref="AgePayloadException">A chunk is truncated or fails authentication.</exception>
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

        using (fileKey)
        {
            var payloadNonce = ReadPayloadNonce(reader);
            var payloadKey = CryptoHelper.HkdfDerive(fileKey.Bytes, payloadNonce, "payload", AgeEncrypt.PayloadKeySize);

            try
            {
                var payloadStart = binaryInput.Position;
                var totalEncrypted = binaryInput.Length - payloadStart;

                if (totalEncrypted == 0)
                    throw new AgePayloadException("payload is empty (no chunks)");

                // The spec requires a seekable reader to verify the final chunk before reporting
                // a length: chunk layout alone cannot tell a truncated file from a shorter one.
                var plaintextLength = AuthenticateFinalChunk(binaryInput, payloadKey, payloadStart, totalEncrypted);
                return new PayloadInfo(payloadKey, payloadStart, totalEncrypted, plaintextLength);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(payloadKey);
                throw;
            }
        }
    }

    /// <summary>
    /// Decrypts the last STREAM chunk with the final flag set and returns the plaintext length
    /// implied by it. Throws if the payload is truncated, tampered with, or ends in an empty
    /// final chunk that has predecessors.
    /// </summary>
    private static long AuthenticateFinalChunk(
        Stream binaryInput, byte[] payloadKey, long payloadStart, long totalEncrypted)
    {
        var totalChunks = ComputeTotalChunks(totalEncrypted);
        var finalIndex = totalChunks - 1;
        var finalChunkStart = finalIndex * StreamEncryption.EncryptedChunkSize;
        var finalChunkEncSize = (int)(totalEncrypted - finalChunkStart);

        if (finalChunkEncSize < StreamEncryption.TagSize)
            throw new AgePayloadException("chunk too small for authentication tag");

        var encChunk = ReadEncryptedChunk(binaryInput, payloadStart + finalChunkStart, finalChunkEncSize);
        var plaintext = StreamEncryption.DecryptChunk(payloadKey, finalIndex, true, encChunk);

        try
        {
            return plaintext.Length == 0 && finalIndex > 0
                ? throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks")
                : finalIndex * StreamEncryption.ChunkSize + plaintext.Length;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
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

        var encChunk = ReadEncryptedChunk(BinaryStream, ciphertextPos, encChunkSize);
        var plaintext = StreamEncryption.DecryptChunk(_payloadKey, chunkIndex, isFinal, encChunk);

        if (isFinal && plaintext.Length == 0 && chunkIndex > 0)
        {
            // Consistency only: the guard condition is plaintext.Length == 0, so the array being
            // abandoned here is zero-length and there is nothing to leak. Cleared anyway so
            // "every decrypted chunk is zeroed on every path" holds without a caveat.
            CryptographicOperations.ZeroMemory(plaintext);
            throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");
        }

        return plaintext;
    }

    private static byte[] ReadEncryptedChunk(Stream stream, long ciphertextPos, int encChunkSize)
    {
        var encChunk = new byte[encChunkSize];
        stream.Position = ciphertextPos;

        var bytesRead = stream.ReadAtLeast(encChunk, encChunkSize, throwOnEndOfStream: false);

        return bytesRead == encChunkSize
            ? encChunk
            : throw new AgePayloadException($"could not read full chunk at offset {ciphertextPos}");
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[AgeEncrypt.PayloadNonceSize];
        var nonceRead = reader.ReadPayloadBytes(payloadNonce);

        return nonceRead == AgeEncrypt.PayloadNonceSize
            ? payloadNonce
            : throw new AgeHeaderException($"expected {AgeEncrypt.PayloadNonceSize}-byte payload nonce, got {nonceRead} bytes");
    }

    // DearmorStream cannot seek, so the decoded ciphertext is buffered in full. Cost is the
    // file's size in memory, as the class remarks note.
    private static MemoryStream Materialize(Stream ciphertext)
    {
        using var dearmored = AsciiArmor.Dearmor(ciphertext);

        var ms = new MemoryStream();
        dearmored.CopyTo(ms);
        ms.Position = 0;

        return ms;
    }

    private static long ComputeTotalChunks(long totalEncryptedPayload)
    {
        if (totalEncryptedPayload <= StreamEncryption.EncryptedChunkSize)
            return 1;

        var fullChunks = totalEncryptedPayload / StreamEncryption.EncryptedChunkSize;
        var remainder = totalEncryptedPayload % StreamEncryption.EncryptedChunkSize;

        return remainder == 0 ? fullChunks : fullChunks + 1;
    }
}