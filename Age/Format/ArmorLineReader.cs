using System.Text;

namespace Age.Format;

/// <summary>
/// Reads armor text as lines ended by LF, with one trailing CR removed: LF and CRLF endings,
/// the way go-age reads armor (armor.go trims "\n", then "\r").
/// </summary>
/// <remarks>
/// StreamReader.ReadLine also ends a line at a lone CR, so armor with CR-only line endings,
/// which go-age rejects, was accepted. Line ends are found with a vectorized search over a
/// buffer rather than character by character, so large armored files are not slowed down.
/// Line length is bounded underneath, by <see cref="NewlineBoundedStream"/>.
/// </remarks>
internal sealed class ArmorLineReader(TextReader inner) : IDisposable
{
    private readonly char[] _buffer = new char[4096];
    private int _start;
    private int _end;

    /// <summary>The next line without its ending, or null at the end of the text.</summary>
    public string? ReadLine()
    {
        StringBuilder? partial = null;

        while (true)
        {
            var pending = _buffer.AsSpan(_start, _end - _start);
            var lf = pending.IndexOf('\n');

            if (lf >= 0)
            {
                _start += lf + 1;
                return WithoutCr(partial is null ? new string(pending[..lf]) : partial.Append(pending[..lf]).ToString());
            }

            (partial ??= new StringBuilder()).Append(pending);

            if (!Fill())
                return partial.Length == 0 ? null : WithoutCr(partial.ToString());
        }
    }

    /// <summary>The next character, or -1 at the end of the text.</summary>
    public int Read() =>
        _start < _end || Fill() ? _buffer[_start++] : -1;

    private bool Fill()
    {
        _start = 0;
        _end = inner.Read(_buffer, 0, _buffer.Length);
        return _end > 0;
    }

    private static string WithoutCr(string line) =>
        line.EndsWith('\r') ? line[..^1] : line;

    public void Dispose() => inner.Dispose();
}
