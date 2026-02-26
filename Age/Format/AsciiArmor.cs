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
        var read = ReadFully(stream, buf);

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

    private static int ReadFully(Stream stream, byte[] buffer)
    {
        var total = 0;

        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }

    public static Stream Dearmor(Stream input)
    {
        var reader = new StreamReader(input, Encoding.ASCII, detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096, leaveOpen: false);

        // Skip leading whitespace (allowed per spec).
        // The old byte-level parser skipped individual whitespace bytes, so
        // "  \n\t-----BEGIN AGE ENCRYPTED FILE-----" is valid. With line-based
        // reading we skip blank lines, then TrimStart the marker line.
        string? line;

        do
        {
            line = reader.ReadLine();
        } while (line != null && line.AsSpan().Trim().Length == 0);

        if (line == null)
            throw new AgeArmorException("empty armored data");

        if (line.TrimStart() != BeginMarker)
            throw new AgeArmorException($"expected begin marker, got: {line}");

        return new DearmorStream(reader);
    }

    public static void Armor(Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var data = inputMs.ToArray();

        var writer = new StreamWriter(output, leaveOpen: true) { NewLine = "\n" };
        writer.WriteLine(BeginMarker);

        var b64 = Convert.ToBase64String(data);

        for (var i = 0; i < b64.Length; i += ColumnsPerLine)
        {
            var len = Math.Min(ColumnsPerLine, b64.Length - i);
            writer.Write(b64.AsSpan(i, len));
            writer.WriteLine();
        }

        writer.WriteLine(EndMarker);
        writer.Flush();
    }

}