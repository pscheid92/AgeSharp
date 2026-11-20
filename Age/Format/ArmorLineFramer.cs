namespace AgeSharp;

/// <summary>One armor line: its bytes without the line ending, and how the line ended.</summary>
/// <remarks>
/// The bytes are borrowed, from the input or from the framer, and valid only until the framer is
/// fed again: take what you need from a line before asking for the next.
/// </remarks>
internal readonly ref struct ArmorLine(ReadOnlySpan<byte> text, bool endedWithCr, bool endedWithLf)
{
    /// <summary>The line, without its LF and without one CR at its end.</summary>
    public ReadOnlySpan<byte> Text { get; } = text;

    /// <summary>Whether a CR at the end of the line was removed.</summary>
    public bool EndedWithCr { get; } = endedWithCr;

    /// <summary>Whether an LF ended the line, rather than the end of the input.</summary>
    public bool EndedWithLf { get; } = endedWithLf;
}

/// <summary>
/// Splits armor bytes into lines, fed as they arrive and never touching a stream. A line ends at
/// an LF, with one CR at its end removed, as go-age reads armor; a lone CR does not end a line.
/// A line may not exceed its bound (<see cref="AgeDecryptOptions.MaxArmorLineBytes"/>), so a line that never ends
/// cannot grow without bound.
/// </summary>
/// <remarks>
/// Nothing is allocated per line. A line that arrives whole is handed out where it lies in the
/// input; only one split across two feeds is copied, into a buffer of the bound's size.
/// </remarks>
internal sealed class ArmorLineFramer(int maxLineBytes = AgeLimits.MaxArmorLineBytes)
{
    private readonly byte[] _pending = new byte[maxLineBytes];
    private int _pendingLength;

    /// <summary>
    /// Takes bytes from the front of <paramref name="input"/> up to and including the next LF,
    /// and returns the line they complete. Without an LF, keeps them all and returns false.
    /// </summary>
    /// <exception cref="AgeArmorException">The line exceeds its bound (<see cref="AgeDecryptOptions.MaxArmorLineBytes"/>).</exception>
    public bool TryTakeLine(ref ReadOnlySpan<byte> input, out ArmorLine line)
    {
        var lf = input.IndexOf((byte)'\n');
        var part = lf < 0 ? input : input[..lf];

        if (_pendingLength + part.Length > maxLineBytes)
            throw new AgeArmorException($"armor line exceeds {maxLineBytes} bytes");

        if (lf < 0)
        {
            part.CopyTo(_pending.AsSpan(_pendingLength));
            _pendingLength += part.Length;
            input = default;
            line = default;
            return false;
        }

        input = input[(lf + 1)..];

        if (_pendingLength == 0)
        {
            line = Line(part, endedWithLf: true);
            return true;
        }

        part.CopyTo(_pending.AsSpan(_pendingLength));
        line = TakePending(_pendingLength + part.Length, endedWithLf: true);
        return true;
    }

    /// <summary>Ends the input: the last line, if it had no LF.</summary>
    public bool TryFinishAtEnd(out ArmorLine line)
    {
        if (_pendingLength == 0)
        {
            line = default;
            return false;
        }

        line = TakePending(_pendingLength, endedWithLf: false);
        return true;
    }

    private ArmorLine TakePending(int length, bool endedWithLf)
    {
        _pendingLength = 0;
        return Line(_pending.AsSpan(0, length), endedWithLf);
    }

    // One CR comes off whether or not an LF followed, as go-age trims it.
    private static ArmorLine Line(ReadOnlySpan<byte> text, bool endedWithLf) =>
        text.Length > 0 && text[^1] == (byte)'\r'
            ? new ArmorLine(text[..^1], endedWithCr: true, endedWithLf)
            : new ArmorLine(text, endedWithCr: false, endedWithLf);
}
