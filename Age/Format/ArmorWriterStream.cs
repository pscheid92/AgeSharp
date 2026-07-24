using System.Buffers.Text;
using System.Text;

namespace AgeSharp;

/// <summary>
/// Push-side counterpart to <see cref="ArmorStream"/>: a write-only stream that
/// ASCII-armors the bytes written to it and forwards the armored text to an
/// underlying destination. The begin marker is emitted lazily on the first write,
/// each 48-byte block becomes a 64-column base64 line, and the end marker is
/// written on <see cref="Dispose(bool)"/>. The destination is never disposed.
/// </summary>
/// <remarks>
/// Output is byte-identical to the pull-side <see cref="ArmorStream"/> (and to the
/// reference implementation): every base64 line — full or the final short one — is
/// followed by a newline, and the footer needs no leading newline of its own.
/// </remarks>
internal sealed class ArmorWriterStream(Stream destination) : Stream
{
    private const int BytesPerLine = 48;   // 48 bytes encode to exactly 64 base64 chars
    private const int CharsPerLine = 64;

    private static readonly byte[] BeginBytes = Encoding.ASCII.GetBytes("-----BEGIN AGE ENCRYPTED FILE-----\n");
    private static readonly byte[] EndBytes = Encoding.ASCII.GetBytes("-----END AGE ENCRYPTED FILE-----\n");

    private readonly byte[] _lineBuffer = new byte[BytesPerLine];
    private readonly byte[] _encoded = new byte[CharsPerLine + 1]; // 64 base64 chars + '\n'
    private int _lineLength;
    private bool _begun;
    private bool _disposed;

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
        => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureBegun();

        while (!buffer.IsEmpty)
        {
            var take = Math.Min(BytesPerLine - _lineLength, buffer.Length);
            buffer[..take].CopyTo(_lineBuffer.AsSpan(_lineLength));
            _lineLength += take;
            buffer = buffer[take..];

            if (_lineLength == BytesPerLine)
                FlushLine();
        }
    }

    private void EnsureBegun()
    {
        if (_begun)
            return;

        destination.Write(BeginBytes);
        _begun = true;
    }

    private void FlushLine()
    {
        Base64.EncodeToUtf8(_lineBuffer.AsSpan(0, _lineLength), _encoded, out _, out var bytesWritten);
        _encoded[bytesWritten] = (byte)'\n';
        destination.Write(_encoded.AsSpan(0, bytesWritten + 1));
        _lineLength = 0;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;

            EnsureBegun();
            if (_lineLength > 0)
                FlushLine();   // final short (or exactly-64) line, newline included
            destination.Write(EndBytes);
            // The destination is caller-owned and is deliberately left open.
        }

        base.Dispose(disposing);
    }

    public override void Flush() => destination.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
