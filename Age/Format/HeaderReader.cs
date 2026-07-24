namespace AgeSharp;

/// <summary>
/// Reads header lines from a stream one byte at a time (so it never consumes
/// payload bytes past the header), delegating all line framing, validation, and
/// size-limit logic to the sans-I/O <see cref="HeaderLineAccumulator"/>. This
/// class is only the fill step: the single place that touches the stream.
/// </summary>
/// <remarks>
/// The sync path pulls one byte per <see cref="ReadLine"/>. The async path calls
/// <see cref="PrefillAsync"/> first — it reads the whole header (through the MAC
/// line) into a line buffer using <c>ReadAsync</c>, after which <see cref="ReadLine"/>
/// serves those buffered lines with no further I/O. Both paths feed the same
/// accumulator, so all parsing (<see cref="Header"/>/<see cref="Stanza"/>) is shared.
/// </remarks>
internal sealed class HeaderReader(Stream stream, int maxLineBytes = 64 * 1024, int maxHeaderBytes = 16 * 1024 * 1024)
{
    private readonly HeaderLineAccumulator _accumulator = new(maxLineBytes, maxHeaderBytes);
    private string? _pushedBack;
    private Queue<string>? _bufferedLines;

    /// <summary>
    /// All raw bytes read so far (for MAC computation).
    /// </summary>
    public ReadOnlySpan<byte> RawBytes => _accumulator.RawBytes;

    /// <summary>
    /// Push a line back so the next ReadLine returns it.
    /// The raw bytes have already been recorded for this line.
    /// </summary>
    public void PushBack(string line)
    {
        _pushedBack = line;
    }

    /// <summary>
    /// Reads a line terminated by LF (\n). Returns the line without the LF.
    /// Returns null at EOF. After <see cref="PrefillAsync"/> this serves the
    /// pre-buffered lines and performs no I/O.
    /// </summary>
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

    /// <summary>
    /// Reads the whole header asynchronously into a line buffer, up to and
    /// including the MAC line (the first line starting with "---") or EOF. After
    /// this, <see cref="ReadLine"/> replays the buffered lines synchronously and
    /// the stream sits at the payload nonce.
    /// </summary>
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

    /// <summary>
    /// Read raw bytes directly (for reading the payload nonce after header).
    /// These bytes are NOT tracked in RawBytes.
    /// </summary>
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

    /// <summary>Asynchronous counterpart to <see cref="ReadPayloadBytes"/>.</summary>
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
