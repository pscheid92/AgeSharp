namespace Age.Fuzz;

/// <summary>A stream that cannot seek, as a pipe, returning at most a given number of bytes a read.</summary>
internal sealed class Pipe(byte[] data, int most) : Stream
{
    private readonly MemoryStream _inner = new(data);

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, Math.Min(count, most));
    public override int Read(Span<byte> buffer) => _inner.Read(buffer[..Math.Min(buffer.Length, most)]);
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>Writes through to another stream, keeping a copy of what was written. Leaves it open.</summary>
internal sealed class Recording(Stream inner) : Stream
{
    private readonly MemoryStream _copy = new();

    public byte[] ToArray()
    {
        lock (_copy)
            return _copy.ToArray();
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count)
    {
        lock (_copy)
            _copy.Write(buffer, offset, count);
        inner.Write(buffer, offset, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        lock (_copy)
            _copy.Write(buffer);
        inner.Write(buffer);
    }

    public override void Flush() => inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
