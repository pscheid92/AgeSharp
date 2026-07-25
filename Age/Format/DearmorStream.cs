namespace AgeSharp;

internal sealed class DearmorStream : Stream
{
    private const int SourceBufferSize = 4096;

    private readonly byte[] _decoded = new byte[ArmorDecoder.MaxDecodedPerLine];
    private readonly ArmorGeometry? _geometry;
    private readonly int _maxArmorLineBytes;

    private readonly Stream _source;

    private readonly byte[] _sourceBuffer = new byte[SourceBufferSize];
    private int _decodedLength;
    private int _decodedOffset;
    private ArmorDecoder _decoder = new();

    private bool _eof;
    private ArmorLineAccumulator _lines;

    private int _bytesToSkipOnNextRead;

    private long _position;
    private int _sourceLength;
    private int _sourceOffset;

    private DearmorStream(Stream source, int maxArmorLineBytes, ArmorGeometry? geometry)
    {
        _source = source;
        _maxArmorLineBytes = maxArmorLineBytes;
        _lines = new ArmorLineAccumulator(maxArmorLineBytes);

        _geometry = geometry;
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

    public static DearmorStream Create(Stream source, int maxArmorLineBytes)
    {
        return new DearmorStream(source, maxArmorLineBytes, ArmorGeometry.TryResolve(source));
    }

    public static async ValueTask<DearmorStream> CreateAsync(Stream source, int maxArmorLineBytes,
        CancellationToken cancellationToken)
    {
        return new DearmorStream(source, maxArmorLineBytes,
            await ArmorGeometry.TryResolveAsync(source, cancellationToken).ConfigureAwait(false));
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    // Base ReadByte allocates a byte[1] per call; the header is read a byte at a time.
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

            if (_sourceOffset >= _sourceLength)
            {
                _sourceLength = _source.Read(_sourceBuffer);
                _sourceOffset = 0;

                if (_sourceLength == 0)
                {
                    FinishAtEof();
                    continue;
                }
            }

            DecodeNextLineFromBuffer();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

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
                    FinishAtEof();
                    continue;
                }
            }

            DecodeNextLineFromBuffer();
        }
    }

    private bool Drain(Span<byte> destination, out int served)
    {
        if (_bytesToSkipOnNextRead > 0)
        {
            var skip = Math.Min(_bytesToSkipOnNextRead, _decodedLength - _decodedOffset);
            _decodedOffset += skip;
            _bytesToSkipOnNextRead -= skip;

            if (_bytesToSkipOnNextRead > 0)
            {
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
        if (_lines.FinishAtEof())
        {
            _decodedLength = _decoder.ProcessLine(_lines.Line, _decoded);
            _decodedOffset = 0;
        }

        _decoder.FinishAtEof();
        _eof = true;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (_geometry is null)
            throw new NotSupportedException();

        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _geometry.DecodedLength + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };

        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));

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
        _bytesToSkipOnNextRead = 0;
        _eof = false;

        // Report what the caller asked for: the skip below is an implementation detail.
        _position = target;

        // Deferred: Seek is synchronous by contract, so this must not read here.
        _bytesToSkipOnNextRead = within;

        return _position;
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
}