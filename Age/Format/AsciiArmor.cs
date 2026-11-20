using System.Text;

namespace Age.Format;

internal static class AsciiArmor
{
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";
    private const int ColumnsPerLine = 64;

    public static bool IsArmored(Stream stream)
    {
        if (!stream.CanSeek)
            return false;

        var pos = stream.Position;
        SkipLeadingWhitespace(stream);

        var marker = Encoding.ASCII.GetBytes(BeginMarker);
        var buf = new byte[marker.Length];
        var read = ReadChunk(stream, buf);

        stream.Position = pos;
        return read == marker.Length && buf.AsSpan().SequenceEqual(marker);
    }

    private static void SkipLeadingWhitespace(Stream stream)
    {
        while (true)
        {
            var b = stream.ReadByte();

            if (b < 0)
                break;

            if (b is ' ' or '\t' or '\r' or '\n')
                continue;

            stream.Position--;
            break;
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