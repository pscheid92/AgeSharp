namespace AgeSharp;

/// <summary>
/// A read-only stream that can look ahead without seeking, so a pipe or a network stream can be
/// inspected before it is read. Bytes looked at are replayed to the next reads, then reading
/// continues from the source. It never reads more from the source than it is asked to look at.
/// </summary>
/// <remarks>Disposing does not dispose the source, which belongs to the caller.</remarks>
internal sealed class PeekableStream(Stream source) : Stream
{
    private byte[] _peeked = [];
    private int _start;
    private int _end;

    /// <summary>
    /// The next <paramref name="count"/> bytes without consuming them: fewer if the source ends
    /// first. Reads from the source only what is not already looked at.
    /// </summary>
    public ReadOnlySpan<byte> Peek(int count)
    {
        if (_end - _start < count)
        {
            Grow(count);

            while (_end - _start < count)
            {
                var read = source.Read(_peeked.AsSpan(_end, _start + count - _end));

                if (read == 0)
                    break;

                _end += read;
            }
        }

        return _peeked.AsSpan(_start, Math.Min(count, _end - _start));
    }

    /// <summary>The asynchronous <see cref="Peek"/>.</summary>
    public async ValueTask<ReadOnlyMemory<byte>> PeekAsync(int count, CancellationToken cancellationToken)
    {
        if (_end - _start < count)
        {
            Grow(count);

            while (_end - _start < count)
            {
                var read = await source.ReadAsync(_peeked.AsMemory(_end, _start + count - _end), cancellationToken).ConfigureAwait(false);

                if (read == 0)
                    break;

                _end += read;
            }
        }

        return _peeked.AsMemory(_start, Math.Min(count, _end - _start));
    }

    // Room for count bytes from _start, keeping what has been looked at and not yet read.
    private void Grow(int count)
    {
        if (_start + count <= _peeked.Length)
            return;

        var grown = new byte[Math.Max(count, _peeked.Length * 2)];
        _peeked.AsSpan(_start, _end - _start).CopyTo(grown);
        _end -= _start;
        _start = 0;
        _peeked = grown;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    // A short read is allowed, so looked-at bytes are replayed without also reading the source.
    public override int Read(Span<byte> buffer) =>
        _start < _end ? Replay(buffer) : source.Read(buffer);

    public override int ReadByte()
    {
        if (_start < _end)
            return _peeked[_start++];

        return source.ReadByte();
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        _start < _end ? ValueTask.FromResult(Replay(buffer.Span)) : source.ReadAsync(buffer, cancellationToken);

    private int Replay(Span<byte> buffer)
    {
        var count = Math.Min(buffer.Length, _end - _start);
        _peeked.AsSpan(_start, count).CopyTo(buffer);
        _start += count;
        return count;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
