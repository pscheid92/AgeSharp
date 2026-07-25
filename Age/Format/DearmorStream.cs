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
    private readonly int _maxArmorLineBytes;
    private readonly ArmorGeometry? _geometry;
    private ArmorLineAccumulator _lines;
    private ArmorDecoder _decoder = new();

    // Decoded bytes served so far. Tracked unconditionally: the facade reads it as
    // Position when handing the stream to the seekable decryptor.
    private long _position;

    private readonly byte[] _sourceBuffer = new byte[SourceBufferSize];
    private int _sourceOffset;
    private int _sourceLength;

    private readonly byte[] _decoded = new byte[ArmorDecoder.MaxDecodedPerLine];
    private int _decodedOffset;
    private int _decodedLength;

    private bool _eof;

    // Sub-line remainder owed from the last Seek, dropped by the next read.
    private int _pendingSkip;

    private DearmorStream(Stream source, int maxArmorLineBytes, ArmorGeometry? geometry)
    {
        _source = source;
        _maxArmorLineBytes = maxArmorLineBytes;
        _lines = new ArmorLineAccumulator(maxArmorLineBytes);

        // Null when the source cannot seek, or is not laid out the way offset
        // translation assumes — either way this stays a forward-only stream.
        _geometry = geometry;
    }

    public static DearmorStream Create(Stream source, int maxArmorLineBytes)
        => new(source, maxArmorLineBytes, ArmorGeometry.TryResolve(source));

    /// <summary>
    /// Asynchronous counterpart to <see cref="Create"/>. Resolving the geometry reads
    /// the source, and the async decrypt path must not block on the caller's stream.
    /// </summary>
    public static async ValueTask<DearmorStream> CreateAsync(Stream source, int maxArmorLineBytes,
                                                             CancellationToken cancellationToken)
        => new(source, maxArmorLineBytes,
               await ArmorGeometry.TryResolveAsync(source, cancellationToken).ConfigureAwait(false));

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    // Stream's base ReadByte allocates a byte[1] per call, and the header is read one
    // byte at a time — so without this an armored header costs one heap allocation per
    // header byte, up to AgeDecryptOptions.MaxHeaderBytes of them before anything is
    // authenticated. The binary path avoids it because FileStream and MemoryStream
    // both override ReadByte themselves.
    public override int ReadByte()
    {
        Span<byte> one = stackalloc byte[1];
        return Read(one) == 1 ? one[0] : -1;
    }

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
        if (_pendingSkip > 0)
        {
            var skip = Math.Min(_pendingSkip, _decodedLength - _decodedOffset);
            _decodedOffset += skip;
            _pendingSkip -= skip;

            if (_pendingSkip > 0)
            {
                // The seeked-to line has not been decoded yet; ask for another.
                served = 0;
                return false;
            }
        }

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
        _position += served;
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
    public override bool CanSeek => _geometry is not null;
    public override bool CanWrite => false;

    public override long Length =>
        _geometry?.DecodedLength ?? throw new NotSupportedException();

    public override long Position
    {
        get => _position;
        set => Seek(value, SeekOrigin.Begin);
    }

    public override void Flush() { }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (_geometry is null)
            throw new NotSupportedException();

        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _geometry.DecodedLength + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };

        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));

        // Jump the source to the start of the line holding the target byte, reset the
        // sans-I/O state to mid-body, then discard the few bytes before it. Reading
        // from a line boundary is what keeps this O(1) rather than a re-scan.
        var lineStart = _geometry.LineStartFor(target);
        var within = ArmorGeometry.OffsetWithinLine(target);

        _source.Position = lineStart;
        _lines = new ArmorLineAccumulator(_maxArmorLineBytes);
        _decoder = new ArmorDecoder();
        _decoder.ResumeInBody();

        _sourceOffset = 0;
        _sourceLength = 0;
        _decodedOffset = 0;
        _decodedLength = 0;
        _pendingSkip = 0;
        _eof = false;

        // The requested position, not the line start it decodes from: the skip below
        // is an implementation detail, and a caller that seeks then asks for Position
        // before reading must see what it asked for. Reporting the line start here
        // makes the next relative seek land mid-line.
        _position = target;

        // Not discarded here: Stream.Seek is synchronous by contract, so reading now
        // would block the caller's stream on the async path. The next Read or
        // ReadAsync drops these bytes instead, whichever the caller uses.
        _pendingSkip = within;

        return _position;
    }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
