using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// Seekable plaintext view over a seekable binary age ciphertext. The plaintext
/// length is derived from the ciphertext layout, <c>Seek</c> maps a plaintext
/// position to the containing 64 KiB STREAM chunk, and the most recently decrypted
/// chunk is cached so repeated small reads within a chunk decrypt it only once.
/// </summary>
/// <remarks>
/// Truncation of the payload can only be detected once a read actually reaches the
/// affected chunk (its authentication tag fails). A structurally impossible payload
/// — empty, or a final chunk too small to hold its tag — is rejected eagerly by the
/// constructor.
/// </remarks>
internal sealed class SeekableDecryptStream : Stream
{
    private readonly byte[] _payloadKey;
    private readonly Stream _ciphertext;
    private readonly bool _ownsStream;
    private readonly long _payloadStart;
    private readonly long _totalEncrypted;
    private readonly long _totalChunks;
    private readonly long _plaintextLength;
    private readonly IAeadCipher _cipher;

    // One-chunk cache: the decrypted plaintext of _cachedChunkIndex (or -1 when empty).
    private readonly byte[] _chunkPlaintext;
    private readonly byte[] _encChunk;
    private long _cachedChunkIndex = -1;
    private int _cachedLength;

    private long _position;
    private bool _disposed;

    public SeekableDecryptStream(byte[] payloadKey, Stream ciphertext, long payloadStart, bool ownsStream)
    {
        _payloadKey = payloadKey;
        _ciphertext = ciphertext;
        _ownsStream = ownsStream;
        _payloadStart = payloadStart;
        _totalEncrypted = ciphertext.Length - payloadStart;

        if (_totalEncrypted == 0)
            throw new AgeAuthenticationException("payload is empty (no chunks)");

        // Both computations can reject a structurally impossible payload; run them
        // before renting buffers so a rejection leaks nothing back to the pool.
        _totalChunks = ComputeTotalChunks(_totalEncrypted);
        _plaintextLength = ComputePlaintextLength(_totalEncrypted);

        _chunkPlaintext = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
        _encChunk = ArrayPool<byte>.Shared.Rent(StreamEncryption.EncryptedChunkSize);
        _cipher = AeadCipher.Create(payloadKey);
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _plaintextLength;

    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var totalRead = 0;

        while (totalRead < buffer.Length && _position >= 0 && _position < _plaintextLength)
        {
            var chunkIndex = _position / StreamEncryption.ChunkSize;
            var offsetInChunk = (int)(_position % StreamEncryption.ChunkSize);

            EnsureChunk(chunkIndex);

            var available = _cachedLength - offsetInChunk;
            if (available <= 0)
                break;

            var toCopy = Math.Min(available, buffer.Length - totalRead);
            _chunkPlaintext.AsSpan(offsetInChunk, toCopy).CopyTo(buffer[totalRead..]);

            totalRead += toCopy;
            _position += toCopy;
        }

        return totalRead;
    }

    private void EnsureChunk(long chunkIndex)
    {
        if (_cachedChunkIndex == chunkIndex)
            return;

        _cachedLength = DecryptChunk(chunkIndex);
        _cachedChunkIndex = chunkIndex;
    }

    private int DecryptChunk(long chunkIndex)
    {
        var isFinal = chunkIndex == _totalChunks - 1;
        var chunkStart = chunkIndex * StreamEncryption.EncryptedChunkSize;
        var encChunkSize = isFinal
            ? (int)(_totalEncrypted - chunkStart)
            : StreamEncryption.EncryptedChunkSize;

        ReadFully(_payloadStart + chunkStart, _encChunk.AsSpan(0, encChunkSize));

        var plaintextLength = encChunkSize - StreamEncryption.TagSize;
        StreamEncryption.DecryptChunk(
            _cipher, chunkIndex, isFinal,
            _encChunk.AsSpan(0, encChunkSize),
            _chunkPlaintext.AsSpan(0, plaintextLength));

        // An empty final chunk after preceding chunks is impossible here: the
        // constructor's ComputePlaintextLength already rejected that layout, so
        // no such stream is ever built. The check lives there, not per-read.
        return plaintextLength;
    }

    private void ReadFully(long position, Span<byte> destination)
    {
        _ciphertext.Position = position;

        var total = 0;
        while (total < destination.Length)
        {
            var read = _ciphertext.Read(destination[total..]);
            if (read == 0)
                throw new AgeAuthenticationException($"could not read full chunk at offset {position}");

            total += read;
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var newPosition = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _plaintextLength + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };

        ArgumentOutOfRangeException.ThrowIfNegative(newPosition, nameof(offset));

        _position = newPosition;
        return _position;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;

            _cipher.Dispose();
            CryptographicOperations.ZeroMemory(_payloadKey);
            CryptographicOperations.ZeroMemory(_chunkPlaintext.AsSpan(0, StreamEncryption.ChunkSize));
            ArrayPool<byte>.Shared.Return(_chunkPlaintext);
            ArrayPool<byte>.Shared.Return(_encChunk);

            if (_ownsStream)
                _ciphertext.Dispose();
        }

        base.Dispose(disposing);
    }

    public override void Flush()
    {
    }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    // The final chunk carries only a tag when the plaintext is empty; every other
    // chunk pairs ChunkSize bytes with a tag. These mirror the layout that the
    // push/pull encrypt paths produce.
    private static long ComputeTotalChunks(long totalEncrypted)
    {
        if (totalEncrypted <= StreamEncryption.EncryptedChunkSize)
            return 1;

        var fullChunks = totalEncrypted / StreamEncryption.EncryptedChunkSize;
        var remainder = totalEncrypted % StreamEncryption.EncryptedChunkSize;

        // No remainder → the last full-sized chunk is itself the final chunk.
        return remainder == 0 ? fullChunks : fullChunks + 1;
    }

    private static long ComputePlaintextLength(long totalEncrypted)
    {
        var totalChunks = ComputeTotalChunks(totalEncrypted);
        var fullChunks = totalChunks - 1;
        var lastChunkEncSize = totalEncrypted - fullChunks * StreamEncryption.EncryptedChunkSize;
        var lastChunkPlainSize = lastChunkEncSize - StreamEncryption.TagSize;

        if (lastChunkPlainSize < 0)
            throw new AgeAuthenticationException("chunk too small for authentication tag");

        // An empty final chunk is only legal when it is the sole chunk (empty
        // plaintext). Because a read never has to touch a zero-length final chunk,
        // this layout must be rejected up front or it would slip past unnoticed —
        // the forward-only path catches the same case as it reads.
        if (lastChunkPlainSize == 0 && fullChunks > 0)
            throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks");

        return fullChunks * StreamEncryption.ChunkSize + lastChunkPlainSize;
    }
}
