using System.Buffers.Text;
using System.Text;

namespace AgeSharp;

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
    private bool _disposed;

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
            var copied = CopyFromScratch(buffer[totalWritten..]);
            if (copied > 0)
            {
                totalWritten += copied;
                continue;
            }

            if (!FillScratch())
                return totalWritten;
        }

        return totalWritten;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var totalWritten = 0;

        while (totalWritten < buffer.Length)
        {
            var copied = CopyFromScratch(buffer.Span[totalWritten..]);
            if (copied > 0)
            {
                totalWritten += copied;
                continue;
            }

            if (!await FillScratchAsync(cancellationToken).ConfigureAwait(false))
                return totalWritten;
        }

        return totalWritten;
    }

    private int CopyFromScratch(Span<byte> dest)
    {
        if (_scratchOffset >= _scratchLength)
            return 0;

        var available = _scratchLength - _scratchOffset;
        var toCopy = Math.Min(available, dest.Length);
        _scratch.AsSpan(_scratchOffset, toCopy).CopyTo(dest);
        _scratchOffset += toCopy;

        return toCopy;
    }

    private bool FillScratch()
    {
        _scratchOffset = 0;

        while (true)
        {
            switch (_phase)
            {
                case Phase.Begin:
                    EmitMarker(BeginBytes, Phase.Body);
                    return true;

                case Phase.Body:
                    var read = ReadFullChunk();
                    if (read == 0)
                    {
                        _phase = Phase.End;
                        continue;
                    }
                    EncodeBodyLine(read);
                    return true;

                case Phase.End:
                    EmitMarker(EndBytes, Phase.Done);
                    return true;

                case Phase.Done:
                    _scratchLength = 0;
                    return false;

                default:
                    throw new InvalidOperationException($"unknown armor phase: {_phase}");
            }
        }
    }

    private async ValueTask<bool> FillScratchAsync(CancellationToken cancellationToken)
    {
        _scratchOffset = 0;

        while (true)
        {
            switch (_phase)
            {
                case Phase.Begin:
                    EmitMarker(BeginBytes, Phase.Body);
                    return true;

                case Phase.Body:
                    var read = await ReadFullChunkAsync(cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        _phase = Phase.End;
                        continue;
                    }
                    EncodeBodyLine(read);
                    return true;

                case Phase.End:
                    EmitMarker(EndBytes, Phase.Done);
                    return true;

                case Phase.Done:
                    _scratchLength = 0;
                    return false;

                default:
                    throw new InvalidOperationException($"unknown armor phase: {_phase}");
            }
        }
    }

    private void EmitMarker(byte[] marker, Phase next)
    {
        marker.CopyTo(_scratch, 0);
        _scratchLength = marker.Length;
        _phase = next;
    }

    private void EncodeBodyLine(int read)
    {
        Base64.EncodeToUtf8(_sourceScratch.AsSpan(0, read), _scratch, out _, out var bytesWritten);
        _scratch[bytesWritten] = (byte)'\n';
        _scratchLength = bytesWritten + 1;
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

    private async ValueTask<int> ReadFullChunkAsync(CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < _sourceScratch.Length)
        {
            var read = await _source.ReadAsync(_sourceScratch.AsMemory(total, _sourceScratch.Length - total), cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _source.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            await _source.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
