using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

// Seek maps a plaintext position to its 64 KiB chunk; the last decrypted chunk is cached.
internal sealed class SeekableDecryptStream : Stream
{
    private readonly byte[] _chunkPlaintext;
    private readonly IAeadCipher _cipher;
    private readonly Stream _ciphertext;
    private readonly byte[] _encChunk;
    private readonly bool _ownsStream;
    private readonly byte[] _payloadKey;
    private readonly long _payloadStart;
    private readonly long _totalChunks;
    private readonly long _totalEncrypted;
    private long _cachedChunkIndex = -1;
    private int _cachedLength;
    private bool _disposed;

    private long _position;

    private SeekableDecryptStream(byte[] payloadKey, Stream ciphertext, long payloadStart, bool ownsStream)
    {
        _payloadKey = payloadKey;
        _ciphertext = ciphertext;
        _ownsStream = ownsStream;
        _payloadStart = payloadStart;
        _totalEncrypted = ciphertext.Length - payloadStart;

        if (_totalEncrypted == 0)
            throw new AgeAuthenticationException("payload is empty (no chunks)");

        _totalChunks = ComputeTotalChunks(_totalEncrypted);
        Length = ComputePlaintextLength(_totalEncrypted);

        _chunkPlaintext = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
        _encChunk = ArrayPool<byte>.Shared.Rent(StreamEncryption.EncryptedChunkSize);
        _cipher = AeadCipher.Create(payloadKey);
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length { get; }

    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    public static SeekableDecryptStream Create(byte[] payloadKey, Stream ciphertext, long payloadStart, bool ownsStream)
    {
        var stream = new SeekableDecryptStream(payloadKey, ciphertext, payloadStart, ownsStream);

        try
        {
            var (encChunkSize, chunkStart) = stream.FinalChunkLayout();
            stream.ReadFully(stream._payloadStart + chunkStart, stream._encChunk.AsSpan(0, encChunkSize));
            stream.CacheFinalChunk(encChunkSize);
        }
        catch
        {
            stream.AbandonResources();
            throw;
        }

        return stream;
    }

    public static async ValueTask<SeekableDecryptStream> CreateAsync(byte[] payloadKey, Stream ciphertext,
        long payloadStart, bool ownsStream,
        CancellationToken cancellationToken)
    {
        var stream = new SeekableDecryptStream(payloadKey, ciphertext, payloadStart, ownsStream);

        try
        {
            var (encChunkSize, chunkStart) = stream.FinalChunkLayout();
            await stream.ReadFullyAsync(stream._payloadStart + chunkStart,
                stream._encChunk.AsMemory(0, encChunkSize), cancellationToken).ConfigureAwait(false);
            stream.CacheFinalChunk(encChunkSize);
        }
        catch
        {
            stream.AbandonResources();
            throw;
        }

        return stream;
    }

    private (int encChunkSize, long chunkStart) FinalChunkLayout()
    {
        return ChunkLayout(_totalChunks - 1);
    }

    // Decrypting the final chunk as final is what authenticates the plaintext length: chunk
// layout alone cannot tell a truncated file from a shorter one.
    private void CacheFinalChunk(int encChunkSize)
    {
        _cachedLength = DecryptLoadedChunk(_totalChunks - 1, encChunkSize);
        _cachedChunkIndex = _totalChunks - 1;
    }

    private void AbandonResources()
    {
        _disposed = true;
        ReleaseResources();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var totalRead = 0;

        while (totalRead < buffer.Length && _position >= 0 && _position < Length)
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

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var totalRead = 0;

        while (totalRead < buffer.Length && _position >= 0 && _position < Length)
        {
            var chunkIndex = _position / StreamEncryption.ChunkSize;
            var offsetInChunk = (int)(_position % StreamEncryption.ChunkSize);

            await EnsureChunkAsync(chunkIndex, cancellationToken).ConfigureAwait(false);

            var available = _cachedLength - offsetInChunk;
            if (available <= 0)
                break;

            var toCopy = Math.Min(available, buffer.Length - totalRead);
            _chunkPlaintext.AsSpan(offsetInChunk, toCopy).CopyTo(buffer.Span[totalRead..]);

            totalRead += toCopy;
            _position += toCopy;
        }

        return totalRead;
    }

    private void EnsureChunk(long chunkIndex)
    {
        if (_cachedChunkIndex == chunkIndex)
            return;

        var (encChunkSize, chunkStart) = ChunkLayout(chunkIndex);
        ReadFully(_payloadStart + chunkStart, _encChunk.AsSpan(0, encChunkSize));
        _cachedLength = DecryptLoadedChunk(chunkIndex, encChunkSize);
        _cachedChunkIndex = chunkIndex;
    }

    private async ValueTask EnsureChunkAsync(long chunkIndex, CancellationToken cancellationToken)
    {
        if (_cachedChunkIndex == chunkIndex)
            return;

        var (encChunkSize, chunkStart) = ChunkLayout(chunkIndex);
        await ReadFullyAsync(_payloadStart + chunkStart, _encChunk.AsMemory(0, encChunkSize), cancellationToken)
            .ConfigureAwait(false);
        _cachedLength = DecryptLoadedChunk(chunkIndex, encChunkSize);
        _cachedChunkIndex = chunkIndex;
    }

    private (int encChunkSize, long chunkStart) ChunkLayout(long chunkIndex)
    {
        var isFinal = chunkIndex == _totalChunks - 1;
        var chunkStart = chunkIndex * StreamEncryption.EncryptedChunkSize;
        var encChunkSize = isFinal
            ? (int)(_totalEncrypted - chunkStart)
            : StreamEncryption.EncryptedChunkSize;

        return (encChunkSize, chunkStart);
    }

    private int DecryptLoadedChunk(long chunkIndex, int encChunkSize)
    {
        var isFinal = chunkIndex == _totalChunks - 1;
        var plaintextLength = encChunkSize - StreamEncryption.TagSize;

        StreamEncryption.DecryptChunk(
            _cipher, chunkIndex, isFinal,
            _encChunk.AsSpan(0, encChunkSize),
            _chunkPlaintext.AsSpan(0, plaintextLength));

        return plaintextLength;
    }

    // A short read is truncation, so it must surface as authentication rather than I/O.
    private void ReadFully(long position, Span<byte> destination)
    {
        _ciphertext.Position = position;

        if (_ciphertext.ReadAtLeast(destination, destination.Length, false) < destination.Length)
            throw new AgeAuthenticationException($"could not read full chunk at offset {position}");
    }

    private async ValueTask ReadFullyAsync(long position, Memory<byte> destination, CancellationToken cancellationToken)
    {
        _ciphertext.Position = position;

        var read = await _ciphertext.ReadAtLeastAsync(destination, destination.Length, false,
            cancellationToken).ConfigureAwait(false);

        if (read < destination.Length)
            throw new AgeAuthenticationException($"could not read full chunk at offset {position}");
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var newPosition = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => Length + offset,
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
            ReleaseResources();
            if (_ownsStream) _ciphertext.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            ReleaseResources();
            if (_ownsStream) await _ciphertext.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void ReleaseResources()
    {
        _cipher.Dispose();
        CryptographicOperations.ZeroMemory(_payloadKey);
        CryptographicOperations.ZeroMemory(_chunkPlaintext.AsSpan(0, StreamEncryption.ChunkSize));
        ArrayPool<byte>.Shared.Return(_chunkPlaintext);
        ArrayPool<byte>.Shared.Return(_encChunk);
    }

    public override void Flush()
    {
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    private static long ComputeTotalChunks(long totalEncrypted)
    {
        if (totalEncrypted <= StreamEncryption.EncryptedChunkSize)
            return 1;

        var fullChunks = totalEncrypted / StreamEncryption.EncryptedChunkSize;
        var remainder = totalEncrypted % StreamEncryption.EncryptedChunkSize;

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

        // A read never touches a zero-length final chunk, so this layout must be rejected here.
        if (lastChunkPlainSize == 0 && fullChunks > 0)
            throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks");

        return fullChunks * StreamEncryption.ChunkSize + lastChunkPlainSize;
    }
}