using System.Buffers.Text;
using System.Text;

namespace Age.Format;

internal sealed class ArmorStream : Stream
{
    private const int BytesPerLine = 48;
    private const int CharsPerLine = 64;

    private static readonly byte[] BeginBytes = Encoding.ASCII.GetBytes("-----BEGIN AGE ENCRYPTED FILE-----\n");
    private static readonly byte[] EndBytes = Encoding.ASCII.GetBytes("-----END AGE ENCRYPTED FILE-----\n");

    private enum Phase { Begin, Body, End, Done }

    private readonly Stream _source;
    private readonly byte[] _sourceScratch = new byte[BytesPerLine];
    private readonly byte[] _scratch = new byte[CharsPerLine + 1];
    private int _scratchOffset;
    private int _scratchLength;
    private Phase _phase = Phase.Begin;

    public ArmorStream(Stream source)
    {
        _source = source;
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

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var totalWritten = 0;

        while (totalWritten < buffer.Length)
        {
            if (_scratchOffset < _scratchLength)
            {
                var available = _scratchLength - _scratchOffset;
                var toCopy = Math.Min(available, buffer.Length - totalWritten);
                _scratch.AsSpan(_scratchOffset, toCopy).CopyTo(buffer[totalWritten..]);
                _scratchOffset += toCopy;
                totalWritten += toCopy;
                continue;
            }

            if (!FillScratch())
                return totalWritten;
        }

        return totalWritten;
    }

    private bool FillScratch()
    {
        _scratchOffset = 0;

        while (true)
        {
            switch (_phase)
            {
                case Phase.Begin:
                    BeginBytes.CopyTo(_scratch, 0);
                    _scratchLength = BeginBytes.Length;
                    _phase = Phase.Body;
                    return true;

                case Phase.Body:
                    var read = ReadFullChunk();
                    if (read == 0)
                    {
                        _phase = Phase.End;
                        continue;
                    }
                    Base64.EncodeToUtf8(_sourceScratch.AsSpan(0, read), _scratch, out _, out var bytesWritten);
                    _scratch[bytesWritten] = (byte)'\n';
                    _scratchLength = bytesWritten + 1;
                    return true;

                case Phase.End:
                    EndBytes.CopyTo(_scratch, 0);
                    _scratchLength = EndBytes.Length;
                    _phase = Phase.Done;
                    return true;

                case Phase.Done:
                    _scratchLength = 0;
                    return false;

                default:
                    throw new InvalidOperationException($"unknown armor phase: {_phase}");
            }
        }
    }

    private int ReadFullChunk()
    {
        var total = 0;
        while (total < _sourceScratch.Length)
        {
            var read = _source.Read(_sourceScratch, total, _sourceScratch.Length - total);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _source.Dispose();

        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
