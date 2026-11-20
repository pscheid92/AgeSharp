using System.Text;

namespace AgeSharp;

internal static class AsciiArmor
{
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";
    private const int ColumnsPerLine = 64;

    // Valid armor has at most this much whitespace before its begin marker: blank lines worth
    // MaxArmorWhitespaceBytes (each counting its length plus one, so up to twice that in raw
    // bytes with CRLF), then the marker line's own indent, within one line's bound, with a
    // line's room to spare: 4 KiB at the defaults. Past this, the input is armor or nothing (a
    // binary file starts with its version line), and the armor reader says which rule it breaks.
    private static int MaxWhitespaceLookahead(AgeDecryptOptions options) =>
        2 * AgeLimits.MaxArmorWhitespaceBytes + 2 * options.MaxArmorLineBytes;

    private static readonly byte[] Marker = Encoding.ASCII.GetBytes(BeginMarker);

    /// <summary>
    /// The input to read age's binary format from: the input itself, or what its armor decodes
    /// to. Detects armor by looking ahead, not by seeking, so it works on a pipe, and looks only
    /// as far as it needs: past leading whitespace and the length of the begin marker.
    /// </summary>
    /// <exception cref="AgeArmorException">
    /// The input is armored and its begin marker is malformed, or armor is required and the
    /// input is not armored.
    /// </exception>
    public static (Stream Binary, bool IsArmored) Open(Stream input, AgeDecryptOptions? options = null)
    {
        options ??= AgeDecryptOptions.Default;
        var peekable = new PeekableStream(input);
        var lookahead = Marker.Length;
        bool? armored;

        while ((armored = Decide(peekable.Peek(lookahead), ref lookahead, options)) is null) { }

        if (armored.Value)
            return (Dearmor(peekable, options), true);

        return options.RequireArmor ? throw NotArmored() : (peekable, false);
    }

    /// <summary>The asynchronous <see cref="Open"/>.</summary>
    /// <exception cref="AgeArmorException">As for <see cref="Open"/>.</exception>
    public static async ValueTask<(Stream Binary, bool IsArmored)> OpenAsync(Stream input, AgeDecryptOptions options, CancellationToken cancellationToken)
    {
        var peekable = new PeekableStream(input);
        var lookahead = Marker.Length;
        bool? armored;

        while ((armored = Decide((await peekable.PeekAsync(lookahead, cancellationToken).ConfigureAwait(false)).Span, ref lookahead, options)) is null) { }

        if (armored.Value)
            return (await DearmorAsync(peekable, cancellationToken, options).ConfigureAwait(false), true);

        return options.RequireArmor ? throw NotArmored() : (peekable, false);
    }

    private static AgeArmorException NotArmored() =>
        new("input is not ASCII-armored, and armor is required");

    /// <summary>Whether a seekable stream holds armor at its position, which is left where it was.</summary>
    public static bool IsArmored(Stream seekable)
    {
        var position = seekable.Position;

        try
        {
            var peekable = new PeekableStream(seekable);
            var lookahead = Marker.Length;
            bool? armored;

            while ((armored = Decide(peekable.Peek(lookahead), ref lookahead, AgeDecryptOptions.Default)) is null) { }

            return armored.Value;
        }
        finally
        {
            seekable.Position = position;
        }
    }

    /// <summary>
    /// Whether <paramref name="prefix"/>, the first <paramref name="lookahead"/> bytes or fewer
    /// if the input ended, starts armor; or null, with <paramref name="lookahead"/> raised, if
    /// more must be read to tell.
    /// </summary>
    private static bool? Decide(ReadOnlySpan<byte> prefix, ref int lookahead, AgeDecryptOptions options)
    {
        var whitespace = prefix.IndexOfAnyExcept(" \t\r\n"u8);
        var inputEnded = prefix.Length < lookahead;
        var bound = MaxWhitespaceLookahead(options);

        if (whitespace < 0)
        {
            // Whitespace to the end of what could be read: not armor if the input ended,
            // armor if there is too much of it to be anything else.
            if (inputEnded)
                return false;

            if (prefix.Length >= bound)
                return true;

            lookahead *= 2;
            return null;
        }

        if (whitespace >= bound)
            return true;

        if (inputEnded || prefix.Length - whitespace >= Marker.Length)
            return prefix[whitespace..].StartsWith(Marker);

        // The whitespace left too little of the lookahead to hold the marker.
        lookahead = whitespace + Marker.Length;
        return null;
    }

    /// <summary>
    /// The bytes an armored input decodes to, read as the returned stream is read. The begin
    /// marker is read here, so input that is not armor is refused at once.
    /// </summary>
    /// <exception cref="AgeArmorException">The input does not start like armor.</exception>
    public static Stream Dearmor(Stream input, AgeDecryptOptions? options = null)
    {
        var dearmored = new DearmorStream(input, (options ?? AgeDecryptOptions.Default).MaxArmorLineBytes);
        dearmored.ReadBegin();
        return dearmored;
    }

    /// <summary>The asynchronous <see cref="Dearmor"/>.</summary>
    /// <exception cref="AgeArmorException">The input does not start like armor.</exception>
    public static async ValueTask<Stream> DearmorAsync(Stream input, CancellationToken cancellationToken, AgeDecryptOptions? options = null)
    {
        var dearmored = new DearmorStream(input, (options ?? AgeDecryptOptions.Default).MaxArmorLineBytes);
        await dearmored.ReadBeginAsync(cancellationToken).ConfigureAwait(false);
        return dearmored;
    }

    public static void Armor(Stream input, Stream output)
    {
        const int bytesPerLine = 48; // 48 bytes encode to exactly 64 base64 chars
        var readBuffer = new byte[bytesPerLine];
        Span<char> charBuffer = stackalloc char[ColumnsPerLine + 4]; // room for padding

        var writer = new StreamWriter(output, leaveOpen: true) { NewLine = "\n" };
        writer.WriteLine(BeginMarker);

        while (true)
        {
            var bytesRead = ReadChunk(input, readBuffer);

            if (bytesRead == 0)
                break;

            Convert.TryToBase64Chars(readBuffer.AsSpan(0, bytesRead), charBuffer, out var charsWritten);
            writer.Write(charBuffer[..charsWritten]);
            writer.WriteLine();
        }

        writer.WriteLine(EndMarker);
        writer.Flush();
    }

    private static int ReadChunk(Stream stream, byte[] buffer)
        => stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);

}