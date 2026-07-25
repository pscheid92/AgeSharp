using System.Buffers.Text;
using System.Text;

namespace AgeSharp;

internal sealed class ArmorWriterStream(Stream destination) : Stream
{
    private const int CharsPerLine = 64;

    private static readonly byte[] BeginBytes = Encoding.ASCII.GetBytes("-----BEGIN AGE ENCRYPTED FILE-----\n");
    private static readonly byte[] EndBytes = Encoding.ASCII.GetBytes("-----END AGE ENCRYPTED FILE-----\n");
    private readonly byte[] _encoded = new byte[CharsPerLine + 1]; // 64 base64 chars + '\n'

    private readonly byte[] _lineBuffer = new byte[ArmorFormat.BytesPerLine];
    private bool _begun;
    private bool _disposed;
    private int _lineLength;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureBegun();

        while (!buffer.IsEmpty)
        {
            var take = Math.Min(ArmorFormat.BytesPerLine - _lineLength, buffer.Length);
            buffer[..take].CopyTo(_lineBuffer.AsSpan(_lineLength));
            _lineLength += take;
            buffer = buffer[take..];

            if (_lineLength == ArmorFormat.BytesPerLine)
                destination.Write(_encoded.AsSpan(0, EncodeLine()));
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await EnsureBegunAsync(cancellationToken).ConfigureAwait(false);

        while (!buffer.IsEmpty)
        {
            var take = Math.Min(ArmorFormat.BytesPerLine - _lineLength, buffer.Length);
            buffer.Span[..take].CopyTo(_lineBuffer.AsSpan(_lineLength));
            _lineLength += take;
            buffer = buffer[take..];

            if (_lineLength == ArmorFormat.BytesPerLine)
                await destination.WriteAsync(_encoded.AsMemory(0, EncodeLine()), cancellationToken)
                    .ConfigureAwait(false);
        }
    }

    private void EnsureBegun()
    {
        if (_begun)
            return;

        destination.Write(BeginBytes);
        _begun = true;
    }

    private ValueTask EnsureBegunAsync(CancellationToken cancellationToken)
    {
        if (_begun)
            return ValueTask.CompletedTask;

        _begun = true;
        return destination.WriteAsync(BeginBytes, cancellationToken);
    }

    // CPU-only: base64-encode the buffered line into _encoded (newline included),
    // reset the line buffer, and return the encoded length to write.
    private int EncodeLine()
    {
        Base64.EncodeToUtf8(_lineBuffer.AsSpan(0, _lineLength), _encoded, out _, out var bytesWritten);
        _encoded[bytesWritten] = (byte)'\n';
        _lineLength = 0;
        return bytesWritten + 1;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;

            EnsureBegun();
            if (_lineLength > 0)
                destination.Write(_encoded.AsSpan(0, EncodeLine())); // final short (or exactly-64) line
            destination.Write(EndBytes);
            // The destination is caller-owned and is deliberately left open.
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;

            await EnsureBegunAsync(default).ConfigureAwait(false);
            if (_lineLength > 0)
                await destination.WriteAsync(_encoded.AsMemory(0, EncodeLine())).ConfigureAwait(false);
            await destination.WriteAsync(EndBytes).ConfigureAwait(false);
            // The destination is caller-owned and is deliberately left open.
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    public override void Flush()
    {
        destination.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return destination.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }
}