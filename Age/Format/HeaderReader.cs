namespace Age.Format;

/// <summary>
/// Reads header lines from a stream byte-by-byte (UTF-8/ASCII),
/// tracking all raw bytes read for MAC computation.
/// This avoids StreamReader buffering that would consume payload bytes.
/// </summary>
internal sealed class HeaderReader
{
    private readonly Stream _stream;
    private readonly MemoryStream _rawBytes = new();
    private string? _pushedBack;

    public HeaderReader(Stream stream)
    {
        _stream = stream;
    }

    /// <summary>
    /// All raw bytes read so far (for MAC computation).
    /// </summary>
    public ReadOnlySpan<byte> RawBytes => _rawBytes.GetBuffer().AsSpan(0, (int)_rawBytes.Length);

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

        var lineBytes = new List<byte>();
        while (true)
        {
            int b = _stream.ReadByte();
            if (b < 0)
            {
                if (lineBytes.Count == 0) return null;
                throw new AgeHeaderException("unexpected end of stream (no trailing newline)");
            }
            _rawBytes.WriteByte((byte)b);
            if (b == '\n')
                break;
            if (b == '\r')
                throw new AgeHeaderException("CR characters are not allowed in age headers");
            if (b > 127)
                throw new AgeHeaderException($"non-ASCII byte 0x{b:X2} in header");
            lineBytes.Add((byte)b);
        }
        return System.Text.Encoding.ASCII.GetString(lineBytes.ToArray());
    }

    /// <summary>
    /// Read raw bytes directly (for reading the payload nonce after header).
    /// These bytes are NOT tracked in RawBytes.
    /// </summary>
    public int ReadPayloadBytes(Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = _stream.Read(buffer[total..]);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
