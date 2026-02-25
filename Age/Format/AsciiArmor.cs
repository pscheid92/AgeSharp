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

        // Skip leading whitespace (whitespace before armor is allowed)
        while (true)
        {
            var b = stream.ReadByte();

            if (b < 0)
                break;

            if (b != ' ' && b != '\t' && b != '\r' && b != '\n')
            {
                stream.Position--;
                break;
            }
        }

        var marker = Encoding.ASCII.GetBytes(BeginMarker);
        var buf = new byte[marker.Length];
        var read = 0;

        while (read < buf.Length)
        {
            var r = stream.Read(buf, read, buf.Length - read);

            if (r == 0)
                break;

            read += r;
        }

        stream.Position = pos;
        return read == marker.Length && buf.AsSpan().SequenceEqual(marker);
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

        var beginLine = ReadLine(allBytes, ref pos)
            ?? throw new AgeArmorException("empty armored data");

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
            var line = ReadLine(allBytes, ref pos)
                ?? throw new AgeArmorException("unexpected end of armored data");

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

        if (line[0] == ' ' || line[0] == '\t' || line[^1] == ' ' || line[^1] == '\t')
            throw new AgeArmorException("whitespace in armor body line");

        if (line.Length > ColumnsPerLine)
            throw new AgeArmorException($"armor body line exceeds {ColumnsPerLine} characters");

        if (lastBodyLineWasShort)
            throw new AgeArmorException("short line in armor body is not the last line");

        if (line.Length < ColumnsPerLine)
            lastBodyLineWasShort = true;

        if (line.Contains('\r') || line.Contains('\n'))
            throw new AgeArmorException("line break within armor body line");

        foreach (var c in line)
        {
            if (!IsBase64Char(c))
                throw new AgeArmorException($"invalid character in armor body: '{c}'");
        }
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

        if (reencoded != line)
            throw new AgeArmorException("non-canonical base64 in armor");

        return decoded;
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

    private static bool IsBase64Char(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '+' or '/' or '=';
}
