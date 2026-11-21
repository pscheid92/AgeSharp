namespace AgeSharp;

/// <summary>
/// A read-only stream of the bytes an armored input decodes to, decoded a line at a time as they
/// are read. The armor's rules are <see cref="ArmorDecoder"/>'s and its lines
/// <see cref="ArmorLineFramer"/>'s; this only moves bytes between them, synchronously or
/// asynchronously. Reading reaches the end of the input, after the end marker, to check what
/// follows it.
/// </summary>
/// <remarks>Disposing does not dispose the input, which belongs to the caller.</remarks>
internal sealed class DearmorStream(Stream input, int maxLineBytes = AgeLimits.MaxArmorLineBytes) : Stream
{
    private readonly ArmorLineFramer _framer = new(maxLineBytes);
    private readonly ArmorDecoder _decoder = new();
    private readonly byte[] _read = new byte[4096];
    private readonly byte[] _decoded = new byte[ArmorDecoder.MaxDecodedPerLine];
    private int _readStart;
    private int _readEnd;
    private int _decodedStart;
    private int _decodedEnd;
    private bool _inputEnded;
    private bool _finished;

    /// <summary>Reads up to and including the begin marker, which refuses input that is not armor.</summary>
    /// <exception cref="AgeFormatException">The input does not start like armor.</exception>
    public void ReadBegin()
    {
        while (!Advance(untilBegun: true))
            Fill();
    }

    /// <summary>Reads up to and including the begin marker; see <see cref="ReadBegin"/>.</summary>
    public async ValueTask ReadBeginAsync(CancellationToken cancellationToken)
    {
        while (!Advance(untilBegun: true))
            await FillAsync(cancellationToken).ConfigureAwait(false);
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty)
            return 0;

        while (!Advance(untilBegun: false))
            Fill();

        return Serve(buffer);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
            return 0;

        while (!Advance(untilBegun: false))
            await FillAsync(cancellationToken).ConfigureAwait(false);

        return Serve(buffer.Span);
    }

    // Decodes from what has been read, without reading more. True when there is something to
    // serve or nothing will ever be (or, with untilBegun, once the begin marker is read); false
    // when more input is needed.
    private bool Advance(bool untilBegun)
    {
        while (_decodedStart == _decodedEnd && !_finished && !(untilBegun && _decoder.HasBegun))
        {
            if (_readStart < _readEnd)
            {
                var pending = new ReadOnlySpan<byte>(_read, _readStart, _readEnd - _readStart);
                var taken = _framer.TryTakeLine(ref pending, out var line);
                _readStart = _readEnd - pending.Length;

                if (taken)
                    Decode(line);

                continue;
            }

            if (!_inputEnded)
                return false;

            if (_framer.TryFinishAtEnd(out var last))
                Decode(last);

            _decoder.Finish();
            _finished = true;
        }

        return true;
    }

    private void Decode(ArmorLine line)
    {
        _decodedStart = 0;
        _decodedEnd = _decoder.TakeLine(line, _decoded);
    }

    private int Serve(Span<byte> buffer)
    {
        var count = Math.Min(buffer.Length, _decodedEnd - _decodedStart);
        _decoded.AsSpan(_decodedStart, count).CopyTo(buffer);
        _decodedStart += count;
        return count;
    }

    private void Fill()
    {
        _readStart = 0;
        _readEnd = input.Read(_read);
        _inputEnded = _readEnd == 0;
    }

    private async ValueTask FillAsync(CancellationToken cancellationToken)
    {
        _readStart = 0;
        _readEnd = await input.ReadAsync(_read, cancellationToken).ConfigureAwait(false);
        _inputEnded = _readEnd == 0;
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
