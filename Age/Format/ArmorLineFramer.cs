using System.Text;

namespace Age.Format;

/// <summary>One armor line: its text without the line ending, and how the line ended.</summary>
/// <param name="Text">The line, without its LF and without one CR at its end.</param>
/// <param name="EndedWithCr">Whether a CR at the end of the line was removed.</param>
/// <param name="EndedWithLf">Whether an LF ended the line, rather than the end of the input.</param>
internal readonly record struct ArmorLine(string Text, bool EndedWithCr, bool EndedWithLf);

/// <summary>
/// Splits armor bytes into lines, fed as they arrive and never touching a stream. A line ends at
/// an LF, with one CR before it removed, as go-age reads armor; a lone CR does not end a line.
/// A line may not exceed <see cref="AgeLimits.MaxArmorLineBytes"/>, so a line that never ends
/// cannot grow without bound.
/// </summary>
/// <remarks>
/// Bytes outside ASCII become '?', as a <see cref="StreamReader"/> with
/// <see cref="Encoding.ASCII"/> made them, so the decoder's refusals name the same character.
/// </remarks>
internal sealed class ArmorLineFramer
{
    private readonly List<byte> _pending = [];

    /// <summary>
    /// Takes bytes from the front of <paramref name="input"/> up to and including the next LF,
    /// and returns the line they complete. Without an LF, keeps them all and returns false.
    /// </summary>
    /// <exception cref="AgeArmorException">The line exceeds <see cref="AgeLimits.MaxArmorLineBytes"/>.</exception>
    public bool TryTakeLine(ref ReadOnlySpan<byte> input, out ArmorLine line)
    {
        var lf = input.IndexOf((byte)'\n');
        var part = lf < 0 ? input : input[..lf];

        if (_pending.Count + part.Length > AgeLimits.MaxArmorLineBytes)
            throw new AgeArmorException($"armor line exceeds {AgeLimits.MaxArmorLineBytes} bytes");

        _pending.AddRange(part);

        if (lf < 0)
        {
            input = default;
            line = default;
            return false;
        }

        input = input[(lf + 1)..];
        line = TakePending(endedWithLf: true);
        return true;
    }

    /// <summary>Ends the input: the last line if it had no LF, or null.</summary>
    public ArmorLine? FinishAtEnd() =>
        _pending.Count == 0 ? null : TakePending(endedWithLf: false);

    private ArmorLine TakePending(bool endedWithLf)
    {
        var text = Encoding.ASCII.GetString(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_pending));
        _pending.Clear();

        // One CR comes off whether or not an LF followed, as the old line reader did at the end.
        return text.EndsWith('\r')
            ? new ArmorLine(text[..^1], EndedWithCr: true, endedWithLf)
            : new ArmorLine(text, EndedWithCr: false, endedWithLf);
    }
}
