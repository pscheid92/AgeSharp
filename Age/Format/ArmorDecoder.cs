using System.Buffers;

namespace AgeSharp;

internal sealed class ArmorDecoder
{
    public const int MaxDecodedPerLine = ArmorFormat.BytesPerLine;

    private static readonly SearchValues<char> Base64Chars =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    private bool _sawFinalLine;

    private State _state = State.BeforeMarker;

    public int ProcessLine(ReadOnlySpan<char> line, Span<byte> destination)
    {
        switch (_state)
        {
            case State.BeforeMarker:
                if (line.Trim().Length == 0)
                    return 0;

                if (!line.TrimStart().SequenceEqual(ArmorFormat.BeginMarker))
                    throw new AgeFormatException($"expected begin marker, got: {new string(line)}");

                _state = State.Body;
                return 0;

            case State.Body:
                if (line.SequenceEqual(ArmorFormat.EndMarker))
                {
                    _state = State.AfterEnd;
                    return 0;
                }

                return DecodeBodyLine(line, destination);

            default:
                if (line.Trim().Length != 0)
                    throw new AgeFormatException("trailing data after end marker");

                return 0;
        }
    }

    // Lines skipped by seeking are never validated; a violating file fails authentication.
    public void ResumeInBody()
    {
        _state = State.Body;
        _sawFinalLine = false;
    }

    public void FinishAtEof()
    {
        switch (_state)
        {
            case State.BeforeMarker:
                throw new AgeFormatException("empty armored data");
            case State.Body:
                throw new AgeFormatException("unexpected end of armored data");
        }
    }

    private int DecodeBodyLine(ReadOnlySpan<char> line, Span<byte> destination)
    {
        ValidateBodyLine(line);

        if (!Convert.TryFromBase64Chars(line, destination, out var bytesWritten))
            throw new AgeFormatException("invalid base64 in armor");

        if (line.Contains('='))
            ValidateCanonicalPadding(line);

        return bytesWritten;
    }

    private void ValidateBodyLine(ReadOnlySpan<char> line)
    {
        if (line.Length == 0)
            throw new AgeFormatException("empty line in armor body");

        if (line[0] is ' ' or '\t' || line[^1] is ' ' or '\t')
            throw new AgeFormatException("whitespace in armor body line");

        if (line.Length > ArmorFormat.ColumnsPerLine)
            throw new AgeFormatException($"armor body line exceeds {ArmorFormat.ColumnsPerLine} characters");

        if (_sawFinalLine)
            throw new AgeFormatException("armor body continues after a line that ended it");

        // A 46- or 47-byte final chunk encodes to a full 64 characters *with* padding, so width
// alone does not prove a line is not the last.
        if (line.Length < ArmorFormat.ColumnsPerLine || line[^1] == '=')
            _sawFinalLine = true;

        var invalid = line.IndexOfAnyExcept(Base64Chars);

        if (invalid >= 0)
            throw new AgeFormatException($"invalid character in armor body: '{line[invalid]}'");
    }

    private static void ValidateCanonicalPadding(ReadOnlySpan<char> line)
    {
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
            throw new AgeFormatException("non-canonical base64 in armor");
    }

    private static int Base64Value(char c)
    {
        return c switch
        {
            >= 'A' and <= 'Z' => c - 'A',
            >= 'a' and <= 'z' => c - 'a' + 26,
            >= '0' and <= '9' => c - '0' + 52,
            '+' => 62,
            '/' => 63,
            _ => throw new AgeFormatException($"invalid base64 character: '{c}'")
        };
    }

    private enum State
    {
        BeforeMarker,
        Body,
        AfterEnd
    }
}