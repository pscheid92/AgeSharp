using System.Buffers;
using System.Text;

namespace Age.Format;

/// <summary>
/// A read-only stream that lazily decodes ASCII-armored (PEM-like) base64 data.
/// Reads one line at a time from the underlying stream, decodes the base64,
/// and serves decoded bytes on demand — avoiding full-file materialization.
/// </summary>
internal sealed class DearmorStream : Stream
{
    private const int ColumnsPerLine = 64;
    private const int MaxDecodedPerLine = 48; // 64 base64 chars = 48 bytes
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";

    private static readonly SearchValues<char> Base64Chars =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    private readonly StreamReader _reader;
    private readonly byte[] _decodeBuffer = new byte[MaxDecodedPerLine];
    private int _decodeOffset;
    private int _decodeCount;
    private bool _finished;
    private bool _bodyEnded;

    public DearmorStream(StreamReader reader)
    {
        _reader = reader;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var totalRead = 0;

        while (totalRead < count)
        {
            if (_decodeCount > 0)
            {
                var toCopy = Math.Min(count - totalRead, _decodeCount);
                Buffer.BlockCopy(_decodeBuffer, _decodeOffset, buffer, offset + totalRead, toCopy);
                _decodeOffset += toCopy;
                _decodeCount -= toCopy;
                totalRead += toCopy;
                continue;
            }

            if (_finished)
                break;

            if (!DecodeNextLine())
                break;
        }

        return totalRead;
    }

    public override int Read(Span<byte> buffer)
    {
        var totalRead = 0;

        while (totalRead < buffer.Length)
        {
            if (_decodeCount > 0)
            {
                var toCopy = Math.Min(buffer.Length - totalRead, _decodeCount);
                _decodeBuffer.AsSpan(_decodeOffset, toCopy).CopyTo(buffer[totalRead..]);
                _decodeOffset += toCopy;
                _decodeCount -= toCopy;
                totalRead += toCopy;
                continue;
            }

            if (_finished)
                break;

            if (!DecodeNextLine())
                break;
        }

        return totalRead;
    }

    private bool DecodeNextLine()
    {
        var line = _reader.ReadLine()
            ?? throw new AgeArmorException("unexpected end of armored data");

        // StreamReader.ReadLine treats a lone CR as a terminator. go-age strips \r only when it
        // follows \n, so a bare CR stays in the line and fails base64; rage rejects it explicitly
        // (ArmoredReadError::LineContainsCr). A bare CR is already rejected here in every case
        // tried — the fragments it creates fail the line-width rules — so this makes the
        // rejection explicit and refactor-proof rather than incidental.
        if (line.Contains('\r'))
            throw new AgeArmorException("armor line contains a carriage return");

        if (line == EndMarker)
        {
            _finished = true;
            ValidateTrailing();
            return false;
        }

        ValidateBodyLine(line);

        if (!Convert.TryFromBase64Chars(line.AsSpan(), _decodeBuffer, out var bytesWritten))
            throw new AgeArmorException("invalid base64 in armor");

        // Padding may appear on a line of any width: a final chunk of 46 bytes encodes to a
        // full 64 characters ending "==", and 47 bytes to 64 characters ending "=". Wherever it
        // appears, the bits the padding covers must be zero. Runs after the decode above so a
        // structurally malformed line fails there first.
        ValidateCanonicalPadding(line.AsSpan());

        _decodeOffset = 0;
        _decodeCount = bytesWritten;
        return true;
    }

    private void ValidateTrailing()
    {
        while (true)
        {
            var ch = _reader.Read();

            if (ch < 0)
                break;

            if (ch is not (' ' or '\t' or '\r' or '\n'))
                throw new AgeArmorException("trailing data after end marker");
        }
    }

    private void ValidateBodyLine(string line)
    {
        if (line.Length == 0)
            throw new AgeArmorException("empty line in armor body");

        if (line[0] is ' ' or '\t' || line[^1] is ' ' or '\t')
            throw new AgeArmorException("whitespace in armor body line");

        if (line.Length > ColumnsPerLine)
            throw new AgeArmorException($"armor body line exceeds {ColumnsPerLine} characters");

        if (_bodyEnded)
            throw new AgeArmorException("short line in armor body is not the last line");

        // The body ends at the first line that cannot be followed by another: one shorter than
        // the full column width, or a full-width line carrying base64 padding (46- and 47-byte
        // final chunks encode to exactly 64 characters).
        if (line.Length < ColumnsPerLine || line[^1] == '=')
            _bodyEnded = true;

        var invalid = line.AsSpan().IndexOfAnyExcept(Base64Chars);

        if (invalid >= 0)
            throw new AgeArmorException($"invalid character in armor body: '{line[invalid]}'");
    }

    private static void ValidateCanonicalPadding(ReadOnlySpan<char> line)
    {
        if (line.Length == 0)
            return;

        var padCount = 0;

        if (line[^1] == '=')
        {
            padCount = 1;

            if (line.Length > 1 && line[^2] == '=')
                padCount = 2;
        }

        if (padCount == 0)
            return;

        var lastDataChar = line[^(padCount + 1)];
        var value = Base64Value(lastDataChar);
        var unusedBits = padCount == 1 ? 2 : 4;
        var mask = (1 << unusedBits) - 1;

        if ((value & mask) != 0)
            throw new AgeArmorException("non-canonical base64 in armor");
    }

    private static int Base64Value(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        _ => throw new AgeArmorException($"invalid base64 character: '{c}'"),
    };

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _reader.Dispose();

        base.Dispose(disposing);
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
