using System.Buffers;

namespace AgeSharp;

/// <summary>
/// Sans-I/O decoder for the ASCII armor format: it is fed whole lines and returns
/// the bytes each one decodes to, enforcing the format's structure as it goes —
/// the begin marker (after any blank lines), the 64-column body with canonical
/// base64, the end marker, and the rule that nothing but whitespace may follow.
/// </summary>
/// <remarks>
/// Holding the prologue here rather than reading it eagerly is what lets the
/// dearmor path be genuinely asynchronous: no line is read until the caller reads,
/// so nothing does blocking I/O on the caller's stream.
/// </remarks>
internal sealed class ArmorDecoder
{
    public const int MaxDecodedPerLine = 48; // 64 base64 chars decode to 48 bytes

    private const int ColumnsPerLine = 64;
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";

    private static readonly SearchValues<char> Base64Chars =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    private enum State
    {
        BeforeMarker,
        Body,
        AfterEnd,
    }

    private State _state = State.BeforeMarker;
    private bool _sawFinalLine;

    /// <summary>
    /// Feeds one complete line and writes what it decodes to into
    /// <paramref name="destination"/> (at most <see cref="MaxDecodedPerLine"/> bytes).
    /// Returns the number of bytes written; marker, blank, and trailing lines
    /// produce none.
    /// </summary>
    /// <exception cref="AgeFormatException">The line violates the armor format.</exception>
    public int ProcessLine(ReadOnlySpan<char> line, Span<byte> destination)
    {
        switch (_state)
        {
            case State.BeforeMarker:
                // Leading blank lines are allowed before the marker.
                if (line.Trim().Length == 0)
                    return 0;

                if (!line.TrimStart().SequenceEqual(BeginMarker))
                    throw new AgeFormatException($"expected begin marker, got: {new string(line)}");

                _state = State.Body;
                return 0;

            case State.Body:
                if (line.SequenceEqual(EndMarker))
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

    /// <summary>
    /// Places the decoder directly in the body, for a reader that has seeked past the
    /// begin marker rather than reading through it.
    /// </summary>
    /// <remarks>
    /// Lines skipped this way are never validated — the position was computed from
    /// the fixed armor geometry, so a file that violates it yields bytes that fail
    /// AEAD authentication rather than decoding to something plausible. Forward reads
    /// still validate every line they pass through.
    /// </remarks>
    public void ResumeInBody()
    {
        _state = State.Body;
        _sawFinalLine = false;
    }

    /// <summary>
    /// Signals end of input. The armor must have been closed by an end marker;
    /// anything else means the data was truncated.
    /// </summary>
    /// <exception cref="AgeFormatException">The armor ended before its end marker.</exception>
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

        // Padding means the payload ran out on this line, whatever its width — so it
        // is validated wherever it appears, not only on short lines.
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

        if (line.Length > ColumnsPerLine)
            throw new AgeFormatException($"armor body line exceeds {ColumnsPerLine} characters");

        if (_sawFinalLine)
            throw new AgeFormatException("armor body continues after a line that ended it");

        // Two things end the body, and the second is easy to miss: a line narrower
        // than the column width, OR a full-width line carrying base64 padding. A
        // final chunk of 46 or 47 bytes encodes to exactly 64 characters *with*
        // padding, so width alone does not prove a line is not the last.
        if (line.Length < ColumnsPerLine || line[^1] == '=')
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

    private static int Base64Value(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        // Unreachable: ValidateBodyLine has already rejected anything outside the
        // base64 alphabet. Present only to make the switch exhaustive.
        _ => throw new AgeFormatException($"invalid base64 character: '{c}'"),
    };
}
