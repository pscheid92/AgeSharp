using System.Buffers;

namespace Age.Format;

/// <summary>
/// The rules of age's ASCII armor, applied line by line and never touching a stream: the
/// whitespace allowed before the begin marker, the body's 64-column base64 lines in canonical
/// form, the end marker, and the whitespace allowed after it, as go-age reads armor.
/// </summary>
internal sealed class ArmorDecoder
{
    /// <summary>The most bytes one body line decodes to: 64 base64 characters.</summary>
    public const int MaxDecodedPerLine = 48;

    private const int ColumnsPerLine = 64;
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";

    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private static readonly SearchValues<char> Base64Chars = SearchValues.Create(Base64Alphabet + "=");

    private Stage _stage = Stage.BeforeBegin;
    private int _leadingWhitespace;
    private int _trailingWhitespace;
    private bool _bodyEnded;

    private enum Stage
    {
        BeforeBegin,
        Body,
        AfterEnd,
    }

    /// <summary>Whether the begin marker has been read.</summary>
    public bool HasBegun =>
        _stage != Stage.BeforeBegin;

    /// <summary>Takes the next line, and writes what it decodes to into <paramref name="decoded"/>.</summary>
    /// <param name="line">The line.</param>
    /// <param name="decoded">At least <see cref="MaxDecodedPerLine"/> bytes.</param>
    /// <returns>How many bytes the line decoded to: zero for anything but a body line.</returns>
    /// <exception cref="AgeArmorException">The line breaks the armor's rules.</exception>
    public int TakeLine(ArmorLine line, Span<byte> decoded)
    {
        switch (_stage)
        {
            case Stage.BeforeBegin:
                TakeLineBeforeBegin(line.Text);
                return 0;

            case Stage.Body when line.Text == EndMarker:
                _stage = Stage.AfterEnd;
                return 0;

            case Stage.Body:
                return DecodeBodyLine(line.Text, decoded);

            default:
                TakeLineAfterEnd(line);
                return 0;
        }
    }

    /// <summary>Ends the input.</summary>
    /// <exception cref="AgeArmorException">The input ended before the begin marker or inside the body.</exception>
    public void Finish()
    {
        switch (_stage)
        {
            case Stage.BeforeBegin:
                throw new AgeArmorException("empty armored data");
            case Stage.Body:
                throw new AgeArmorException("unexpected end of armored data");
        }
    }

    // Leading whitespace is allowed: blank lines are skipped, then the marker line is trimmed at
    // its start. Only the blank lines count against the allowance, as in go-age.
    private void TakeLineBeforeBegin(string line)
    {
        if (line.AsSpan().Trim().Length == 0)
        {
            if ((_leadingWhitespace += line.Length + 1) > AgeLimits.MaxArmorWhitespaceBytes)
                throw new AgeArmorException(
                    $"more than {AgeLimits.MaxArmorWhitespaceBytes} bytes of whitespace before the armor header");

            return;
        }

        if (line.TrimStart() != BeginMarker)
            throw new AgeArmorException($"expected begin marker, got: {line}");

        _stage = Stage.Body;
    }

    private int DecodeBodyLine(string line, Span<byte> decoded)
    {
        ValidateBodyLine(line);

        if (!Convert.TryFromBase64Chars(line.AsSpan(), decoded, out var bytesWritten))
            throw new AgeArmorException("invalid base64 in armor");

        // Padding may appear on a line of any width: a final chunk of 46 bytes encodes to a full
        // 64 characters ending "==", and 47 bytes to 64 characters ending "=". Wherever it
        // appears, the bits the padding covers must be zero. Checked after the decode, so a
        // structurally malformed line fails there first.
        ValidateCanonicalPadding(line.AsSpan());
        return bytesWritten;
    }

    // After the footer only whitespace may follow, and less than go-age's allowance of it
    // (armor.go reads at most that much and rejects a full read). Counted byte by byte, line
    // endings included, as the bytes arrived.
    private void TakeLineAfterEnd(ArmorLine line)
    {
        foreach (var c in line.Text)
            TakeTrailing(c);

        if (line.EndedWithCr)
            TakeTrailing('\r');

        if (line.EndedWithLf)
            TakeTrailing('\n');
    }

    private void TakeTrailing(char c)
    {
        if (c is not (' ' or '\t' or '\r' or '\n'))
            throw new AgeArmorException("trailing data after end marker");

        if (++_trailingWhitespace >= AgeLimits.MaxArmorWhitespaceBytes)
            throw new AgeArmorException(
                $"{AgeLimits.MaxArmorWhitespaceBytes} or more bytes of whitespace after the armor footer");
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
        var padCount = line[^1] != '=' ? 0 : line.Length > 1 && line[^2] == '=' ? 2 : 1;

        if (padCount == 0)
            return;

        // The character was validated as base64 already, so it is in the alphabet.
        var value = Base64Alphabet.IndexOf(line[^(padCount + 1)]);
        var mask = (1 << (padCount == 1 ? 2 : 4)) - 1;

        if ((value & mask) != 0)
            throw new AgeArmorException("non-canonical base64 in armor");
    }
}
