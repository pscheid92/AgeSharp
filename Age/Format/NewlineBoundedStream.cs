namespace Age.Format;

/// <summary>
/// A read-only pass-through stream that caps the number of bytes that may pass
/// without a line terminator (CR or LF). This lets the armor reader keep using
/// the fast <see cref="StreamReader.ReadLine"/> path while still bounding memory:
/// a hostile stream with a multi-gigabyte line cannot be buffered, because the
/// limit trips during the underlying read instead.
/// </summary>
internal sealed class NewlineBoundedStream(Stream inner, int maxLineBytes) : Stream
{
    private int _run; // bytes seen since the last CR/LF

    public override int Read(byte[] buffer, int offset, int count)
    {
        var n = inner.Read(buffer, offset, count);
        Scan(buffer.AsSpan(offset, n));
        return n;
    }

    public override int Read(Span<byte> buffer)
    {
        var n = inner.Read(buffer);
        Scan(buffer[..n]);
        return n;
    }

    private void Scan(ReadOnlySpan<byte> bytes)
    {
        // Fast path: when the carried run plus this whole chunk fits the limit,
        // no line inside the chunk can violate it. One backward vectorized scan
        // updates the carried run, so the bound costs ~one SIMD pass per read.
        if (_run + bytes.Length <= maxLineBytes)
        {
            var lastNl = bytes.LastIndexOfAny((byte)'\n', (byte)'\r');
            _run = lastNl < 0 ? _run + bytes.Length : bytes.Length - 1 - lastNl;
            return;
        }

        // Slow path (a line has accumulated near the limit — hostile input):
        // walk newline-to-newline to find where the run is broken or exceeded.
        while (!bytes.IsEmpty)
        {
            var nl = bytes.IndexOfAny((byte)'\n', (byte)'\r');
            var lineLen = nl < 0 ? bytes.Length : nl;

            if (_run + lineLen > maxLineBytes)
                throw new AgeArmorException($"armor line exceeds {maxLineBytes} bytes");

            if (nl < 0)
            {
                _run += bytes.Length;
                return;
            }

            _run = 0;
            bytes = bytes[(nl + 1)..];
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            inner.Dispose();

        base.Dispose(disposing);
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
