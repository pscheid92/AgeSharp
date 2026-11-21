using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// The plaintext of a binary age file on a seekable stream, readable from any position: a
/// position maps to its chunk, which is read, decrypted and kept until a read needs another.
/// </summary>
/// <remarks>
/// <para>
/// Opening decrypts the final chunk, as the spec requires of a seekable reader: the layout alone
/// cannot tell a truncated file from a shorter one, so <see cref="Length"/> is reported only once
/// the final chunk has authenticated.
/// </para>
/// <para>
/// Chunk boundaries follow from the position, so a failed read does not poison the stream: the
/// position stays where the read began, and a retry reads the same chunk again. Every decrypted
/// chunk is cleared when the next replaces it and on dispose. The ciphertext stream is the
/// caller's and is left open; reading moves its position.
/// </para>
/// </remarks>
internal sealed class SeekableDecryptStream : Stream
{
    private readonly Stream _ciphertext;
    private readonly PayloadKey _payloadKey;
    private readonly long _payloadStart;
    private readonly long _payloadLength;
    private readonly long _chunks;
    private readonly byte[] _encrypted = ArrayPool<byte>.Shared.Rent(StreamEncryption.EncryptedChunkSize);
    private readonly byte[] _plaintext = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
    private long _cachedChunk = -1;
    private int _cachedLength;
    private long _position;
    private long _length;
    private bool _disposed;

    private SeekableDecryptStream(PayloadKey payloadKey, Stream ciphertext, long payloadStart)
    {
        _payloadKey = payloadKey;
        _ciphertext = ciphertext;
        _payloadStart = payloadStart;
        _payloadLength = ciphertext.Length - payloadStart;
        _chunks = Math.Max(1, (_payloadLength + StreamEncryption.EncryptedChunkSize - 1) / StreamEncryption.EncryptedChunkSize);
    }

    /// <summary>Opens the payload that starts at <paramref name="ciphertext"/>'s position, authenticating its final chunk.</summary>
    /// <exception cref="AgeAuthenticationException">The payload is empty, truncated, or its final chunk fails authentication.</exception>
    public static SeekableDecryptStream Open(PayloadKey payloadKey, Stream ciphertext)
    {
        var stream = new SeekableDecryptStream(payloadKey, ciphertext, ciphertext.Position);

        try
        {
            stream.CheckLayout();
            stream.Decrypt(stream._chunks - 1, stream.ReadChunk(stream._chunks - 1));
            stream._length = stream.LengthFromFinalChunk();
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>The asynchronous <see cref="Open"/>.</summary>
    public static async ValueTask<SeekableDecryptStream> OpenAsync(PayloadKey payloadKey, Stream ciphertext, CancellationToken cancellationToken)
    {
        var stream = new SeekableDecryptStream(payloadKey, ciphertext, ciphertext.Position);

        try
        {
            stream.CheckLayout();
            stream.Decrypt(stream._chunks - 1, await stream.ReadChunkAsync(stream._chunks - 1, cancellationToken).ConfigureAwait(false));
            stream._length = stream.LengthFromFinalChunk();
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    // The same checks, in the same words, as reading in order makes.
    private void CheckLayout()
    {
        if (_payloadLength == 0)
            throw new AgeAuthenticationException("payload is empty (no chunks)");

        if (ChunkLength(_chunks - 1) < StreamEncryption.TagSize)
            throw new AgeAuthenticationException("chunk too small for authentication tag");
    }

    private long LengthFromFinalChunk() =>
        _cachedLength == 0 && _chunks > 1
            ? throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks")
            : (_chunks - 1) * StreamEncryption.ChunkSize + _cachedLength;

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;

    /// <summary>The plaintext length, authenticated by the final chunk.</summary>
    public override long Length => _disposed ? throw new ObjectDisposedException(GetType().Name) : _length;

    public override long Position
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _position;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };

        ArgumentOutOfRangeException.ThrowIfNegative(position, nameof(offset));
        return _position = position;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var start = _position;

        try
        {
            var total = 0;

            while (total < buffer.Length && _position < _length)
            {
                var chunk = _position / StreamEncryption.ChunkSize;

                if (chunk != _cachedChunk)
                    Decrypt(chunk, ReadChunk(chunk));

                total += Serve(buffer[total..]);
            }

            return total;
        }
        catch
        {
            _position = start;
            throw;
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var start = _position;

        try
        {
            var total = 0;

            while (total < buffer.Length && _position < _length)
            {
                var chunk = _position / StreamEncryption.ChunkSize;

                if (chunk != _cachedChunk)
                    Decrypt(chunk, await ReadChunkAsync(chunk, cancellationToken).ConfigureAwait(false));

                total += Serve(buffer.Span[total..]);
            }

            return total;
        }
        catch
        {
            _position = start;
            throw;
        }
    }

    /// <summary>
    /// Writes from the position to the end straight from each decrypted chunk, which is cleared
    /// when the next replaces it. Stream's own CopyTo would copy through a pooled buffer and
    /// return it uncleared.
    /// </summary>
    public override void CopyTo(Stream destination, int bufferSize)
    {
        ValidateCopyToArguments(destination, bufferSize);
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (_position < _length)
        {
            var chunk = _position / StreamEncryption.ChunkSize;

            if (chunk != _cachedChunk)
                Decrypt(chunk, ReadChunk(chunk));

            var (offset, count) = Remaining();
            destination.Write(_plaintext, offset, count);
            _position += count;
        }

        ClearCache();
    }

    public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
    {
        ValidateCopyToArguments(destination, bufferSize);
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (_position < _length)
        {
            var chunk = _position / StreamEncryption.ChunkSize;

            if (chunk != _cachedChunk)
                Decrypt(chunk, await ReadChunkAsync(chunk, cancellationToken).ConfigureAwait(false));

            var (offset, count) = Remaining();
            await destination.WriteAsync(_plaintext.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
            _position += count;
        }

        ClearCache();
    }

    // A copy runs to the end, so nothing it decrypted is read again unless the caller seeks back:
    // the last chunk is cleared rather than kept until dispose.
    private void ClearCache()
    {
        CryptographicOperations.ZeroMemory(_plaintext.AsSpan(0, _cachedLength));
        _cachedChunk = -1;
        _cachedLength = 0;
    }

    // The cached chunk's plaintext from the position on.
    private (int Offset, int Count) Remaining()
    {
        var offset = (int)(_position % StreamEncryption.ChunkSize);
        return (offset, _cachedLength - offset);
    }

    private int Serve(Span<byte> buffer)
    {
        var (offset, available) = Remaining();
        var count = Math.Min(available, buffer.Length);
        _plaintext.AsSpan(offset, count).CopyTo(buffer);
        _position += count;
        return count;
    }

    private int ChunkLength(long chunk) =>
        chunk == _chunks - 1
            ? (int)(_payloadLength - chunk * StreamEncryption.EncryptedChunkSize)
            : StreamEncryption.EncryptedChunkSize;

    private int ReadChunk(long chunk)
    {
        var length = ChunkLength(chunk);
        _ciphertext.Position = _payloadStart + chunk * StreamEncryption.EncryptedChunkSize;
        return Check(chunk, _ciphertext.ReadAtLeast(_encrypted.AsSpan(0, length), length, throwOnEndOfStream: false), length);
    }

    private async ValueTask<int> ReadChunkAsync(long chunk, CancellationToken cancellationToken)
    {
        var length = ChunkLength(chunk);
        _ciphertext.Position = _payloadStart + chunk * StreamEncryption.EncryptedChunkSize;
        var read = await _ciphertext.ReadAtLeastAsync(_encrypted.AsMemory(0, length), length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        return Check(chunk, read, length);
    }

    // The stream may have shrunk since it was opened.
    private int Check(long chunk, int read, int length) =>
        read == length
            ? length
            : throw new AgeAuthenticationException($"could not read full chunk at offset {_payloadStart + chunk * StreamEncryption.EncryptedChunkSize}");

    // Decrypts a chunk into the cache, replacing what was there, which is cleared first, so a
    // failure leaves nothing decrypted behind.
    private void Decrypt(long chunk, int length)
    {
        ClearCache();

        StreamEncryption.DecryptChunk(_payloadKey.Cipher, chunk, chunk == _chunks - 1, _encrypted.AsSpan(0, length), _plaintext);

        _cachedChunk = chunk;
        _cachedLength = length - StreamEncryption.TagSize;
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            _payloadKey.Dispose();
            CryptographicOperations.ZeroMemory(_plaintext.AsSpan(0, StreamEncryption.ChunkSize));
            ArrayPool<byte>.Shared.Return(_plaintext);
            ArrayPool<byte>.Shared.Return(_encrypted);
        }

        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
