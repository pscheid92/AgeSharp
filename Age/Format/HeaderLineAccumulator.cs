using System.Runtime.InteropServices;
using System.Text;

namespace AgeSharp;

// Sans-I/O line framing for the header, bounding both line and total size.
internal sealed class HeaderLineAccumulator(int maxLineBytes, int maxHeaderBytes)
{
    private readonly List<byte> _lineBytes = [];
    private readonly MemoryStream _rawBytes = new();

    public ReadOnlySpan<byte> RawBytes => _rawBytes.GetBuffer().AsSpan(0, (int)_rawBytes.Length);

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