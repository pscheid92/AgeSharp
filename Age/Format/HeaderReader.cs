using System.Text;

namespace Age.Format;

/// <summary>
/// Reads header lines from a stream byte-by-byte (UTF-8/ASCII),
/// tracking all raw bytes read for MAC computation.
/// This avoids StreamReader buffering that would consume payload bytes.
/// </summary>
internal sealed class HeaderReader(Stream stream)
{
    // Defensive bounds so a malformed/hostile header can't exhaust memory before
    // any authentication happens. Both are far above any legitimate age header:
    // the largest built-in stanza line (an ML-KEM enc argument) is ~1.5 KiB, and
    // real headers carry a handful of recipients.
    private const int MaxLineLength = 64 * 1024;       // 64 KiB per line
    private const int MaxHeaderLength = 16 * 1024 * 1024; // 16 MiB total

    private readonly MemoryStream _rawBytes = new();
    private string? _pushedBack;

    /// <summary>
    /// All raw bytes read so far (for MAC computation).
    /// </summary>
    public ReadOnlySpan<byte> RawBytes =>
        _rawBytes.GetBuffer().AsSpan(0, (int)_rawBytes.Length);

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
        if (_pushedBack == null)
            return ReadRawLine();

        var line = _pushedBack;
        _pushedBack = null;
        return line;
    }

    private string? ReadRawLine()
    {
        var lineBytes = new List<byte>();

        while (true)
        {
            var b = ReadAndTrackByte();

            if (b < 0)
                return lineBytes.Count == 0
                    ? null
                    : throw new AgeHeaderException("unexpected end of stream (no trailing newline)");

            if (b == '\n')
                break;

            ValidateByte(b);

            if (lineBytes.Count >= MaxLineLength)
                throw new AgeHeaderException($"header line exceeds {MaxLineLength} bytes");

            lineBytes.Add((byte)b);
        }

        return Encoding.ASCII.GetString(lineBytes.ToArray());
    }

    private int ReadAndTrackByte()
    {
        var b = stream.ReadByte();

        if (b >= 0)
        {
            if (_rawBytes.Length >= MaxHeaderLength)
                throw new AgeHeaderException($"header exceeds {MaxHeaderLength} bytes");

            _rawBytes.WriteByte((byte)b);
        }

        return b;
    }

    private static void ValidateByte(int b)
    {
        switch (b)
        {
            case '\r':
                throw new AgeHeaderException("CR characters are not allowed in age headers");
            case > 127:
                throw new AgeHeaderException($"non-ASCII byte 0x{b:X2} in header");
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