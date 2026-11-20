using System.Runtime.InteropServices;
using System.Text;

namespace AgeSharp;

/// <summary>
/// Splits header bytes into lines, fed one byte at a time and never touching a stream: what a
/// header line may contain, how large the header may grow, and the raw bytes the MAC covers.
/// Where the bytes come from (a synchronous read, an asynchronous one) is the reader's business.
/// </summary>
internal sealed class HeaderLineFramer
{
    private readonly List<byte> _line = [];
    private readonly MemoryStream _raw = new();

    /// <summary>Every byte fed so far, line endings included: what the MAC is computed over.</summary>
    public ReadOnlySpan<byte> RawBytes =>
        _raw.GetBuffer().AsSpan(0, (int)_raw.Length);

    /// <summary>Takes the next byte, and returns the line it completes, without its LF, or null.</summary>
    /// <exception cref="AgeHeaderException">
    /// The byte is a CR or not ASCII, or the header would exceed <see cref="AgeLimits.MaxHeaderBytes"/>.
    /// As in go-age, a line has no bound of its own beyond the header's.
    /// </exception>
    public string? Feed(byte b)
    {
        if (_raw.Length >= AgeLimits.MaxHeaderBytes)
            throw new AgeHeaderException($"header exceeds {AgeLimits.MaxHeaderBytes} bytes");

        _raw.WriteByte(b);

        if (b == (byte)'\n')
        {
            var line = Encoding.ASCII.GetString(CollectionsMarshal.AsSpan(_line));
            _line.Clear();
            return line;
        }

        switch (b)
        {
            case (byte)'\r':
                throw new AgeHeaderException("CR characters are not allowed in age headers");
            case > 127:
                throw new AgeHeaderException($"non-ASCII byte 0x{b:X2} in header");
        }

        _line.Add(b);
        return null;
    }

    /// <summary>Ends the input: null at a line boundary.</summary>
    /// <exception cref="AgeHeaderException">The input ended partway through a line.</exception>
    public string? FinishAtEnd() =>
        _line.Count == 0 ? null : throw new AgeHeaderException("unexpected end of stream (no trailing newline)");
}
