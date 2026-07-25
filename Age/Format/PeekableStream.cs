namespace AgeSharp;

// Lookahead rather than seeking, so armor detection works on a pipe. Never disposes inner.
internal sealed class PeekableStream(Stream inner) : Stream
{
    private int _length;
    private int _offset;
    private byte[] _peeked = [];

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public int Peek(Span<byte> destination)
    {
        var needed = Grow(destination.Length);

        while (_length < needed)
        {
            var read = inner.Read(_peeked.AsSpan(_length, needed - _length));
            if (read == 0)
                break;

            _length += read;
        }

        return Serve(destination);
    }

    public async ValueTask<int> PeekAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
    {
        var needed = Grow(destination.Length);

        while (_length < needed)
        {
            var read = await inner.ReadAsync(_peeked.AsMemory(_length, needed - _length), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                break;

            _length += read;
        }

        return Serve(destination.Span);
    }

    // Tops the buffer up rather than replacing it: replacing would drop peeked-but-unread
    // bytes, and the source has already yielded them.
    private int Grow(int count)
    {
        var needed = _offset + count;

        if (_peeked.Length < needed)
            Array.Resize(ref _peeked, needed);

        return needed;
    }

    private int Serve(Span<byte> destination)
    {
        var available = Math.Min(_length - _offset, destination.Length);
        _peeked.AsSpan(_offset, available).CopyTo(destination);
        return available;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        // A short read is legal, so replayed bytes never force a read on the source.
        var replayed = Drain(buffer);
        return replayed > 0 ? replayed : inner.Read(buffer);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var replayed = Drain(buffer.Span);
        return replayed > 0
            ? ValueTask.FromResult(replayed)
            : inner.ReadAsync(buffer, cancellationToken);
    }

    private int Drain(Span<byte> destination)
    {
        var available = _length - _offset;
        if (available <= 0 || destination.IsEmpty)
            return 0;

        var toCopy = Math.Min(available, destination.Length);
        _peeked.AsSpan(_offset, toCopy).CopyTo(destination);
        _offset += toCopy;
        return toCopy;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
}