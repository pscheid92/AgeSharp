namespace AgeSharp;

/// <summary>
///     A read-only pass-through stream that lets the first bytes of a source be
///     inspected and then read again. This is what makes armor detection work on a
///     pipe or socket: deciding whether input is armored needs <em>lookahead</em>,
///     not seeking, and lookahead is available on every stream.
/// </summary>
/// <remarks>
///     Ownership follows the library-wide rule: this wrapper never disposes the
///     stream it wraps. It holds only a small managed buffer, so leaving one
///     undisposed leaks nothing.
/// </remarks>
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

    /// <summary>
    ///     Reads up to <paramref name="destination" />.Length bytes and copies them
    ///     there <em>without consuming them</em> — a subsequent <see cref="Read(Span{byte})" />
    ///     returns the same bytes first. Returns the number of bytes available, which
    ///     is short only at end of stream.
    /// </summary>
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

    /// <summary>Asynchronous counterpart to <see cref="Peek" />.</summary>
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

    // Sizes the buffer to hold `count` bytes past whatever has already been replayed,
    // and returns that target fill level. Peeking tops the buffer up rather than
    // replacing it: replacing would drop any peeked-but-not-yet-read bytes on the
    // floor, and those bytes are gone from the source for good.
    private int Grow(int count)
    {
        var needed = _offset + count;

        if (_peeked.Length < needed)
            Array.Resize(ref _peeked, needed);

        return needed;
    }

    // Copies the unread window into the caller's buffer without consuming it.
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
        // Serve the peeked bytes first. Returning fewer bytes than asked for is
        // allowed by the Stream contract, so this never has to touch the source
        // while replayed bytes remain — which keeps a blocking read off the path.
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