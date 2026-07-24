namespace AgeSharp;

/// <summary>
/// A read-only stream that lazily decodes ASCII-armored (PEM-like) base64 data.
/// It pulls raw bytes from the source, frames them into lines with
/// <see cref="ArmorLineAccumulator"/>, and decodes each line with
/// <see cref="ArmorDecoder"/> — so memory stays bounded by one 48-byte decoded line
/// plus a small read buffer, whatever the file's size.
/// </summary>
/// <remarks>
/// The sync and async read paths differ only in how bytes are fetched from the
/// source; all framing, validation, and decoding is shared sans-I/O state. That is
/// what lets armored input be decrypted without any blocking I/O on the caller's
/// stream. The source is never disposed — ownership stays with the caller.
/// </remarks>
internal sealed class DearmorStream : Stream
{
    private const int SourceBufferSize = 4096;

    private readonly Stream _source;
    private readonly ArmorLineAccumulator _lines;
    private readonly ArmorDecoder _decoder = new();

    private readonly byte[] _sourceBuffer = new byte[SourceBufferSize];
    private int _sourceOffset;
    private int _sourceLength;

    private readonly byte[] _decoded = new byte[ArmorDecoder.MaxDecodedPerLine];
    private int _decodedOffset;
    private int _decodedLength;

    private bool _eof;

    public DearmorStream(Stream source, int maxArmorLineBytes)
    {
        _source = source;
        _lines = new ArmorLineAccumulator(maxArmorLineBytes);
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        while (true)
        {
            if (Drain(buffer, out var served))
                return served;

            if (_eof)
                return 0;

            // Refill only when the current batch is spent; decoding it may yield
            // several lines, and the loop re-enters to drain each in turn.
            if (_sourceOffset >= _sourceLength)
            {
                _sourceLength = _source.Read(_sourceBuffer);
                _sourceOffset = 0;

                if (_sourceLength == 0)
                {
                    // May still decode a final line that lacked a trailing newline,
                    // so loop rather than returning — Drain picks those bytes up.
                    FinishAtEof();
                    continue;
                }
            }

            DecodeNextLineFromBuffer();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (Drain(buffer.Span, out var served))
                return served;

            if (_eof)
                return 0;

            if (_sourceOffset >= _sourceLength)
            {
                _sourceLength = await _source.ReadAsync(_sourceBuffer, cancellationToken).ConfigureAwait(false);
                _sourceOffset = 0;

                if (_sourceLength == 0)
                {
                    // May still decode a final line that lacked a trailing newline,
                    // so loop rather than returning — Drain picks those bytes up.
                    FinishAtEof();
                    continue;
                }
            }

            DecodeNextLineFromBuffer();
        }
    }

    // Copies whatever is already decoded into the caller's buffer. Returns true when
    // it produced something (or the caller asked for nothing), meaning Read can return.
    private bool Drain(Span<byte> destination, out int served)
    {
        var available = _decodedLength - _decodedOffset;

        if (destination.IsEmpty)
        {
            served = 0;
            return true;
        }

        if (available <= 0)
        {
            served = 0;
            return false;
        }

        served = Math.Min(available, destination.Length);
        _decoded.AsSpan(_decodedOffset, served).CopyTo(destination);
        _decodedOffset += served;
        return true;
    }

    // CPU-only: consume buffered source bytes until one line completes, then decode
    // it. Shared by both read paths — only the fill above differs.
    private void DecodeNextLineFromBuffer()
    {
        while (_sourceOffset < _sourceLength)
        {
            if (!_lines.Feed(_sourceBuffer[_sourceOffset++]))
                continue;

            _decodedLength = _decoder.ProcessLine(_lines.Line, _decoded);
            _decodedOffset = 0;
            return;
        }
    }

    private void FinishAtEof()
    {
        // A final line without a trailing newline is still a line, and may decode.
        if (_lines.FinishAtEof())
        {
            _decodedLength = _decoder.ProcessLine(_lines.Line, _decoded);
            _decodedOffset = 0;
        }

        _decoder.FinishAtEof();
        _eof = true;
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
