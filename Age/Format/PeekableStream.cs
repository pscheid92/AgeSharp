namespace AgeSharp;

/// <summary>
/// A read-only pass-through stream that lets the first bytes of a source be
/// inspected and then read again. This is what makes armor detection work on a
/// pipe or socket: deciding whether input is armored needs <em>lookahead</em>,
/// not seeking, and lookahead is available on every stream.
/// </summary>
/// <remarks>
/// Ownership follows the library-wide rule: this wrapper never disposes the
/// stream it wraps. It holds only a small managed buffer, so leaving one
/// undisposed leaks nothing.
/// </remarks>
internal sealed class PeekableStream(Stream inner) : Stream
{
    private byte[] _peeked = [];
    private int _offset;
    private int _length;

    /// <summary>
    /// Reads up to <paramref name="destination"/>.Length bytes and copies them
    /// there <em>without consuming them</em> — a subsequent <see cref="Read(Span{byte})"/>
    /// returns the same bytes first. Returns the number of bytes available, which
    /// is short only at end of stream.
    /// </summary>
    public int Peek(Span<byte> destination)
    {
        var buffer = new byte[destination.Length];
        var total = 0;

        while (total < buffer.Length)
        {
            var read = inner.Read(buffer.AsSpan(total));
            if (read == 0)
                break;

            total += read;
        }

        Retain(buffer, total);
        buffer.AsSpan(0, total).CopyTo(destination);
        return total;
    }

    /// <summary>Asynchronous counterpart to <see cref="Peek"/>.</summary>
    public async ValueTask<int> PeekAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var buffer = new byte[destination.Length];
        var total = 0;

        while (total < buffer.Length)
        {
            var read = await inner.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;

            total += read;
        }

        Retain(buffer, total);
        buffer.AsMemory(0, total).CopyTo(destination);
        return total;
    }

    private void Retain(byte[] buffer, int length)
    {
        _peeked = buffer;
        _offset = 0;
        _length = length;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        // Serve the peeked bytes first. Returning fewer bytes than asked for is
        // allowed by the Stream contract, so this never has to touch the source
        // while replayed bytes remain — which keeps a blocking read off the path.
        var replayed = Drain(buffer);
        return replayed > 0 ? replayed : inner.Read(buffer);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

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
