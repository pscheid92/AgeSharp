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
    private bool _disposed;
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
        // Reading would pull from the disposed inner EncryptStream's returned buffers.
        ObjectDisposedException.ThrowIf(_disposed, this);

        var total = 0;

        while (true)
        {
            total += EmitReady(buffer[total..]);

            if (total == buffer.Length || _phase == Phase.Done)
                return total;

            FillScratch(_phase == Phase.Body ? ReadBodyChunk() : 0);
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    // The same steps as Read, with the body read awaited: the only I/O this stream does.
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var total = 0;

        while (true)
        {
            total += EmitReady(buffer.Span[total..]);

            if (total == buffer.Length || _phase == Phase.Done)
                return total;

            FillScratch(_phase == Phase.Body ? await ReadBodyChunkAsync(cancellationToken).ConfigureAwait(false) : 0);
        }
    }

    private int EmitReady(Span<byte> dest)
    {
        var toCopy = Math.Min(_scratchLength - _scratchOffset, dest.Length);
        _scratch.AsSpan(_scratchOffset, toCopy).CopyTo(dest);
        _scratchOffset += toCopy;
        return toCopy;
    }

    // The next line into the scratch buffer. In the body, read is how many bytes of binary
    // input it encodes; none means the body has ended and the END line follows.
    private void FillScratch(int read)
    {
        _scratchOffset = 0;

        switch (_phase)
        {
            case Phase.Begin:
                BeginBytes.CopyTo(_scratch, 0);
                _scratchLength = BeginBytes.Length;
                _phase = Phase.Body;
                break;

            case Phase.Body when read > 0:
                Base64.EncodeToUtf8(_sourceScratch.AsSpan(0, read), _scratch, out _, out var bytesWritten);
                _scratch[bytesWritten] = (byte)'\n';
                _scratchLength = bytesWritten + 1;
                break;

            case Phase.Body:
                EndBytes.CopyTo(_scratch, 0);
                _scratchLength = EndBytes.Length;
                _phase = Phase.End;
                break;

            case Phase.End:
                _scratchLength = 0;
                _phase = Phase.Done;
                break;
        }
    }

    private int ReadBodyChunk()
        => _source.ReadAtLeast(_sourceScratch, _sourceScratch.Length, throwOnEndOfStream: false);

    private ValueTask<int> ReadBodyChunkAsync(CancellationToken cancellationToken)
        => _source.ReadAtLeastAsync(_sourceScratch, _sourceScratch.Length, throwOnEndOfStream: false, cancellationToken);

    // Guarded for the same reason as the streams it wraps: _source is an EncryptStream whose
    // Dispose returns pooled buffers, so forwarding a second Dispose would return them twice.
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _source.Dispose();
        }

        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
