namespace AgeSharp;

// Sans-I/O, so the sync and async dearmor paths share all framing. Line is a span over a
// reused buffer: one line per 48 bytes means fresh strings would scale with file size.
internal sealed class ArmorLineAccumulator(int maxLineBytes)
{
    private char[] _buffer = new char[128];
    private int _lineLength;
    private int _pending;

    // Valid only until the next Feed/FinishAtEof — it aliases the reused buffer.
    public ReadOnlySpan<char> Line => _buffer.AsSpan(0, _lineLength);

    public bool Feed(byte b)
    {
        if (b == (byte)'\n')
        {
            CompleteLine();
            return true;
        }

        if (_pending >= maxLineBytes)
            throw new AgeFormatException($"armor line exceeds {maxLineBytes} bytes");

        if (_pending == _buffer.Length)
            Array.Resize(ref _buffer, Math.Min(_buffer.Length * 2, maxLineBytes + 1));

        _buffer[_pending++] = (char)b;
        return false;
    }

    public bool FinishAtEof()
    {
        if (_pending == 0)
            return false;

        CompleteLine();
        return true;
    }

    private void CompleteLine()
    {
        // Tolerate CRLF: the terminator is not part of the line's content.
        _lineLength = _pending > 0 && _buffer[_pending - 1] == '\r' ? _pending - 1 : _pending;
        _pending = 0;
    }
}