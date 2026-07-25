using System.Runtime.InteropServices;
using System.Text;

namespace AgeSharp;

/// <summary>
///     Sans-I/O core of header reading: it is fed one raw byte at a time and yields a
///     completed line each time it sees an LF, while tracking every byte for the
///     header MAC and enforcing the per-line and whole-header size limits. It never
///     touches a stream — <see cref="HeaderReader" /> (sync) and any async driver push
///     bytes into it, so all line framing, validation, and limit logic is shared.
/// </summary>
internal sealed class HeaderLineAccumulator(int maxLineBytes, int maxHeaderBytes)
{
    private readonly List<byte> _lineBytes = [];
    private readonly MemoryStream _rawBytes = new();

    /// <summary>All bytes fed so far (for MAC computation over the raw header).</summary>
    public ReadOnlySpan<byte> RawBytes => _rawBytes.GetBuffer().AsSpan(0, (int)_rawBytes.Length);

    /// <summary>
    ///     Feeds one byte. Returns the completed line (without the trailing LF) when
    ///     that byte is an LF, otherwise <c>null</c> to signal that more bytes are
    ///     needed. Throws <see cref="AgeFormatException" /> on a disallowed byte or a
    ///     size-limit breach.
    /// </summary>
    public string? Feed(byte b)
    {
        Track(b);

        if (b == (byte)'\n')
        {
            var line = Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(_lineBytes));
            _lineBytes.Clear();
            return line;
        }

        Validate(b);

        if (_lineBytes.Count >= maxLineBytes)
            throw new AgeFormatException($"header line exceeds {maxLineBytes} bytes");

        _lineBytes.Add(b);
        return null;
    }

    /// <summary>
    ///     Signals end-of-stream. Returns <c>null</c> when no partial line is pending
    ///     (a clean line boundary), otherwise throws — a header line must end with LF.
    /// </summary>
    public string? FinishAtEof()
    {
        return _lineBytes.Count == 0
            ? null
            : throw new AgeFormatException("unexpected end of stream (no trailing newline)");
    }

    private void Track(byte b)
    {
        if (_rawBytes.Length >= maxHeaderBytes)
            throw new AgeFormatException($"header exceeds {maxHeaderBytes} bytes");

        _rawBytes.WriteByte(b);
    }

    private static void Validate(byte b)
    {
        switch (b)
        {
            case (byte)'\r':
                throw new AgeFormatException("CR characters are not allowed in age headers");
            case > 127:
                throw new AgeFormatException($"non-ASCII byte 0x{b:X2} in header");
        }
    }
}