namespace Age.Crypto;

internal sealed class RandomAccessDecryptStream(AgeRandomAccess reader, long initialOffset) : Stream
{
    private long _position = initialOffset;
    private readonly long _length = reader.PlaintextLength;

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

        var read = reader.ReadAt(_position, buffer);
        _position += read;

        return read;
    }

    // Both copies go through the reader, which writes each decrypted chunk directly and zeroes
    // it; Stream's defaults would leave plaintext in an uncleared pooled buffer.
    public override void CopyTo(Stream destination, int bufferSize)
    {
        ValidateCopyToArguments(destination, bufferSize);
        reader.CopyTo(_position, destination);
        _position = Math.Max(_position, _length);
    }

    public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
    {
        ValidateCopyToArguments(destination, bufferSize);
        await reader.CopyToAsync(_position, destination, cancellationToken).ConfigureAwait(false);
        _position = Math.Max(_position, _length);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var newPos = origin switch
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

    public override void Flush()
    {
    }

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();
}