namespace AgeSharp;

/// <summary>
///     Sans-I/O line framing for ASCII armor: fed one raw byte at a time, it completes a
///     line each time it sees an LF and enforces the per-line size limit. It never
///     touches a stream, so the synchronous and asynchronous dearmor paths share all
///     framing and bounding logic.
/// </summary>
/// <remarks>
///     Mirrors <see cref="HeaderLineAccumulator" />, with three differences the armor
///     format requires. A trailing CR is stripped rather than rejected, because armored
///     files travel through text channels and routinely arrive CRLF-terminated. There is
///     no whole-input byte cap, because an armor body is legitimately unbounded — only
///     each line is. And the completed line is exposed as a span over a reused buffer
///     rather than a fresh string: an armored file has one line per 48 plaintext bytes,
///     so allocating a string each time would make decoding churn proportional to file
///     size even though its working set is constant.
/// </remarks>
internal sealed class ArmorLineAccumulator(int maxLineBytes)
{
    private char[] _buffer = new char[128];
    private int _lineLength;
    private int _pending;

    /// <summary>
    ///     The most recently completed line, without its terminator. Valid only after
    ///     <see cref="Feed" /> or <see cref="FinishAtEof" /> returned <c>true</c>, and only
    ///     until the next call.
    /// </summary>
    public ReadOnlySpan<char> Line => _buffer.AsSpan(0, _lineLength);

    /// <summary>
    ///     Feeds one byte. Returns <c>true</c> when that byte completed a line, which is
    ///     then available in <see cref="Line" />.
    /// </summary>
    /// <exception cref="AgeFormatException">The line exceeded the size limit.</exception>
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

        // Armor is ASCII; anything else fails base64 validation downstream.
        _buffer[_pending++] = (char)b;
        return false;
    }

    /// <summary>
    ///     Signals end of input. Returns <c>true</c> when an unterminated final line was
    ///     pending, which is then available in <see cref="Line" />.
    /// </summary>
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