using System.Buffers.Text;

namespace AgeSharp;

/// <summary>
/// The push half of armoring: bytes written to it reach <c>destination</c> as ASCII armor, in the
/// same lines <see cref="ArmorStream"/> produces. Disposing writes the last line and the end
/// marker; the destination stays open.
/// </summary>
internal sealed class ArmorWriterStream(Stream destination) : Stream
{
    private const int BytesPerLine = 48;
    private const int CharsPerLine = 64;

    private static ReadOnlySpan<byte> BeginLine => "-----BEGIN AGE ENCRYPTED FILE-----\n"u8;
    private static ReadOnlySpan<byte> EndLine => "-----END AGE ENCRYPTED FILE-----\n"u8;

    private readonly byte[] _line = new byte[BytesPerLine];
    private readonly byte[] _encoded = new byte[CharsPerLine + 1];
    private int _lineLength;
    private bool _begun;
    private bool _disposed;

    public override void Write(byte[] buffer, int offset, int count) =>
        Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_begun)
        {
            _begun = true;
            destination.Write(BeginLine);
        }

        while (!buffer.IsEmpty)
        {
            buffer = Take(buffer);

            if (_lineLength == BytesPerLine)
                destination.Write(_encoded, 0, EncodeLine());
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_begun)
        {
            _begun = true;
            await destination.WriteAsync(BeginLine.ToArray(), cancellationToken).ConfigureAwait(false);
        }

        while (!buffer.IsEmpty)
        {
            var rest = Take(buffer.Span);
            buffer = buffer[(buffer.Length - rest.Length)..];

            if (_lineLength == BytesPerLine)
                await destination.WriteAsync(_encoded.AsMemory(0, EncodeLine()), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Writes what is left: the begin marker if nothing was written, the last line, the end marker.</summary>
    public void Finish()
    {
        if (!_begun)
            destination.Write(BeginLine);

        if (_lineLength > 0)
            destination.Write(_encoded, 0, EncodeLine());

        destination.Write(EndLine);
    }

    /// <summary>The asynchronous <see cref="Finish"/>.</summary>
    public async ValueTask FinishAsync(CancellationToken cancellationToken)
    {
        if (!_begun)
            await destination.WriteAsync(BeginLine.ToArray(), cancellationToken).ConfigureAwait(false);

        if (_lineLength > 0)
            await destination.WriteAsync(_encoded.AsMemory(0, EncodeLine()), cancellationToken).ConfigureAwait(false);

        await destination.WriteAsync(EndLine.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private ReadOnlySpan<byte> Take(ReadOnlySpan<byte> buffer)
    {
        var take = Math.Min(BytesPerLine - _lineLength, buffer.Length);
        buffer[..take].CopyTo(_line.AsSpan(_lineLength));
        _lineLength += take;
        return buffer[take..];
    }

    private int EncodeLine()
    {
        Base64.EncodeToUtf8(_line.AsSpan(0, _lineLength), _encoded, out _, out var written);
        _encoded[written] = (byte)'\n';
        _lineLength = 0;
        return written + 1;
    }

    // Disposing only stops further writes: Finish is the encrypt writer's to call, so that a
    // failed file is never given an end marker.
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
        base.Dispose(disposing);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => destination.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => destination.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
