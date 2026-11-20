using System.Text;

namespace AgeSharp;

internal static class AsciiArmor
{
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";
    private const int ColumnsPerLine = 64;

    // Valid armor has at most this much whitespace before its begin marker: blank lines worth
    // MaxArmorWhitespaceBytes (each counting its length plus one, so up to twice that in raw
    // bytes with CRLF), then the marker line's own indent, within one line's bound. Past this,
    // the input is armor or nothing, and the armor reader says which rule it breaks.
    private const int MaxWhitespaceLookahead = 4 * AgeLimits.MaxArmorLineBytes;

    /// <summary>
    /// The input to read age's binary format from: the input itself, or what its armor decodes
    /// to. Detects armor by looking ahead, not by seeking, so it works on a pipe, and looks only
    /// as far as it needs: past leading whitespace and the length of the begin marker.
    /// </summary>
    /// <exception cref="AgeArmorException">The input is armored, and its begin marker is malformed.</exception>
    public static (Stream Binary, bool IsArmored) Open(Stream input)
    {
        var peekable = new PeekableStream(input);

        return StartsWithArmor(peekable)
            ? (Dearmor(peekable), true)
            : (peekable, false);
    }

    /// <summary>Whether a seekable stream holds armor at its position, which is left where it was.</summary>
    public static bool IsArmored(Stream seekable)
    {
        var position = seekable.Position;

        try
        {
            return StartsWithArmor(new PeekableStream(seekable));
        }
        finally
        {
            seekable.Position = position;
        }
    }

    private static bool StartsWithArmor(PeekableStream input)
    {
        var marker = Encoding.ASCII.GetBytes(BeginMarker);
        var lookahead = marker.Length;

        while (true)
        {
            var prefix = input.Peek(lookahead);
            var whitespace = prefix.IndexOfAnyExcept(" \t\r\n"u8);
            var inputEnded = prefix.Length < lookahead;

            if (whitespace < 0)
            {
                // Whitespace to the end of what could be read: not armor if the input ended,
                // armor if there is too much of it to be anything else.
                if (inputEnded)
                    return false;

                if (prefix.Length >= MaxWhitespaceLookahead)
                    return true;

                lookahead *= 2;
                continue;
            }

            if (whitespace >= MaxWhitespaceLookahead)
                return true;

            if (inputEnded || prefix.Length - whitespace >= marker.Length)
                return prefix[whitespace..].StartsWith(marker);

            // The whitespace left too little of the lookahead to hold the marker.
            lookahead = whitespace + marker.Length;
        }
    }

    /// <summary>
    /// The bytes an armored input decodes to, read as the returned stream is read. The begin
    /// marker is read here, so input that is not armor is refused at once.
    /// </summary>
    /// <exception cref="AgeArmorException">The input does not start like armor.</exception>
    public static Stream Dearmor(Stream input)
    {
        var dearmored = new DearmorStream(input);
        dearmored.ReadBegin();
        return dearmored;
    }

    /// <summary>The asynchronous <see cref="Dearmor"/>.</summary>
    /// <exception cref="AgeArmorException">The input does not start like armor.</exception>
    public static async ValueTask<Stream> DearmorAsync(Stream input, CancellationToken cancellationToken)
    {
        var dearmored = new DearmorStream(input);
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