using System.Buffers;
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

    public static MemoryStream Dearmor(Stream input)
    {
        using var ms = new MemoryStream();
        input.CopyTo(ms);
        var allBytes = ms.ToArray();
        var pos = 0;

        // Skip leading whitespace (allowed per spec)
        while (pos < allBytes.Length && IsWhitespace(allBytes[pos]))
            pos++;

        var beginLine = ReadLine(allBytes, ref pos) ?? throw new AgeArmorException("empty armored data");
        if (beginLine != BeginMarker)
            throw new AgeArmorException($"expected begin marker, got: {beginLine}");

        var bodyBytes = ReadBodyLines(allBytes, ref pos);

        // Skip trailing whitespace (allowed per spec)
        while (pos < allBytes.Length)
        {
            if (!IsWhitespace(allBytes[pos]))
                throw new AgeArmorException("trailing data after end marker");

            pos++;
        }

        return new MemoryStream(bodyBytes.ToArray());
    }

    private static List<byte> ReadBodyLines(byte[] allBytes, ref int pos)
    {
        var bodyBytes = new List<byte>();
        var lastBodyLineWasShort = false;

        while (true)
        {
            var line = ReadLine(allBytes, ref pos) ?? throw new AgeArmorException("unexpected end of armored data");

            if (line == EndMarker)
                return bodyBytes;

            ValidateBodyLine(line, ref lastBodyLineWasShort);
            bodyBytes.AddRange(DecodeBase64Line(line));
        }
    }

    private static void ValidateBodyLine(string line, ref bool lastBodyLineWasShort)
    {
        if (line.Length == 0)
            throw new AgeArmorException("empty line in armor body");

        if (line[0] is ' ' or '\t' || line[^1] is ' ' or '\t')
            throw new AgeArmorException("whitespace in armor body line");

        if (line.Length > ColumnsPerLine)
            throw new AgeArmorException($"armor body line exceeds {ColumnsPerLine} characters");

        if (lastBodyLineWasShort)
            throw new AgeArmorException("short line in armor body is not the last line");

        if (line.Length < ColumnsPerLine)
            lastBodyLineWasShort = true;

        ValidateBase64Chars(line);
    }

    private static byte[] DecodeBase64Line(string line)
    {
        byte[] decoded;

        try
        {
            decoded = Convert.FromBase64String(line);
        }
        catch (FormatException ex)
        {
            throw new AgeArmorException($"invalid base64 in armor: {ex.Message}");
        }

        var reencoded = Convert.ToBase64String(decoded);

        return reencoded == line
            ? decoded
            : throw new AgeArmorException("non-canonical base64 in armor");
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

    private static string? ReadLine(byte[] data, ref int pos)
    {
        if (pos >= data.Length)
            return null;

        var start = pos;

        while (pos < data.Length && data[pos] != '\n')
            pos++;

        var end = pos;

        if (pos < data.Length)
            pos++; // skip the \n

        // Strip trailing \r if present
        if (end > start && data[end - 1] == '\r')
            end--;

        return Encoding.ASCII.GetString(data, start, end - start);
    }

    private static bool IsWhitespace(byte b) =>
        b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';

    private static readonly SearchValues<char> Base64Chars =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    private static void ValidateBase64Chars(string line)
    {
        var invalid = line.AsSpan().IndexOfAnyExcept(Base64Chars);

        if (invalid >= 0)
            throw new AgeArmorException($"invalid character in armor body: '{line[invalid]}'");
    }
}