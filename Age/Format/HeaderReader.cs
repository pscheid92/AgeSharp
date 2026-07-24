namespace AgeSharp;

/// <summary>
/// Reads header lines from a stream one byte at a time (so it never consumes
/// payload bytes past the header), delegating all line framing, validation, and
/// size-limit logic to the sans-I/O <see cref="HeaderLineAccumulator"/>. This
/// class is only the fill step: the single place that touches the stream.
/// </summary>
internal sealed class HeaderReader(Stream stream, int maxLineBytes = 64 * 1024, int maxHeaderBytes = 16 * 1024 * 1024)
{
    private readonly HeaderLineAccumulator _accumulator = new(maxLineBytes, maxHeaderBytes);
    private string? _pushedBack;

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
    /// Returns null at EOF.
    /// </summary>
    public string? ReadLine()
    {
        if (_pushedBack != null)
        {
            var line = _pushedBack;
            _pushedBack = null;
            return line;
        }

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
}
