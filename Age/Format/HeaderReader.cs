namespace AgeSharp;

// Reads header lines and tracks the raw bytes the MAC is computed over. PrefillAsync lets
// the async path buffer the whole header up front, after which parsing is pure.
internal sealed class HeaderReader(Stream stream, int maxLineBytes = 64 * 1024, int maxHeaderBytes = 16 * 1024 * 1024)
{
    private readonly HeaderLineAccumulator _accumulator = new(maxLineBytes, maxHeaderBytes);
    private Queue<string>? _bufferedLines;
    private string? _pushedBack;

    public ReadOnlySpan<byte> RawBytes => _accumulator.RawBytes;

    public void PushBack(string line)
    {
        _pushedBack = line;
    }

    public string? ReadLine()
    {
        if (_pushedBack != null)
        {
            var line = _pushedBack;
            _pushedBack = null;
            return line;
        }

        if (_bufferedLines != null)
            return _bufferedLines.Count > 0 ? _bufferedLines.Dequeue() : null;

        while (true)
        {
            var b = stream.ReadByte();

            if (b < 0)
                return _accumulator.FinishAtEof();

            var line = _accumulator.Feed((byte)b);
            if (line != null)
                return line;
        }
    }

    // Buffers the header so the sync parse that follows does no I/O.
    public async ValueTask PrefillAsync(CancellationToken cancellationToken)
    {
        var lines = new Queue<string>();
        var one = new byte[1];

        while (true)
        {
            var read = await stream.ReadAsync(one.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                // Throws on a partial trailing line; otherwise a clean boundary.
                _accumulator.FinishAtEof();
                break;
            }

            if (_accumulator.Feed(one[0]) is { } line)
            {
                lines.Enqueue(line);

                // The MAC line is the only header line starting with "---"; stop there,
                // leaving the stream positioned at the payload nonce.
                if (line.StartsWith("---", StringComparison.Ordinal))
                    break;
            }
        }

        _bufferedLines = lines;
    }

    public int ReadPayloadBytes(Span<byte> buffer)
    {
        var total = 0;

        while (total < buffer.Length)
        {
            var read = stream.Read(buffer[total..]);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }

    public async ValueTask<int> ReadPayloadBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var total = 0;

        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }
}