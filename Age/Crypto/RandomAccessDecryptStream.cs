namespace Age.Crypto;

internal sealed class RandomAccessDecryptStream : Stream
{
    private readonly AgeRandomAccess _reader;
    private long _position;
    private readonly long _length;

    public RandomAccessDecryptStream(AgeRandomAccess reader, long initialOffset)
    {
        _reader = reader;
        _position = initialOffset;
        _length = reader.PlaintextLength;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;
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
        if (_position >= _length)
            return 0;

        int read = _reader.ReadAt(_position, buffer);
        _position += read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long newPos = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };

        ArgumentOutOfRangeException.ThrowIfNegative(newPos, nameof(offset));
        _position = newPos;
        return _position;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
