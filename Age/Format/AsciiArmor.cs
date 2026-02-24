using System.Text;

namespace Age.Format;

internal static class AsciiArmor
{
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";
    private const int ColumnsPerLine = 64;

    public static bool IsArmored(Stream stream)
    {
        if (!stream.CanSeek) return false;
        long pos = stream.Position;

        // Skip leading whitespace (whitespace before armor is allowed)
        int b;
        while (true)
        {
            b = stream.ReadByte();
            if (b < 0) break;
            if (b != ' ' && b != '\t' && b != '\r' && b != '\n')
            {
                // Put back this byte by seeking back 1
                stream.Position--;
                break;
            }
        }

        var marker = Encoding.ASCII.GetBytes(BeginMarker);
        var buf = new byte[marker.Length];
        int read = 0;
        while (read < buf.Length)
        {
            int r = stream.Read(buf, read, buf.Length - read);
            if (r == 0) break;
            read += r;
        }
        stream.Position = pos;
        return read == marker.Length && buf.AsSpan().SequenceEqual(marker);
    }

    public static MemoryStream Dearmor(Stream input)
    {
        // Read all bytes to process manually
        using var ms = new MemoryStream();
        input.CopyTo(ms);
        var allBytes = ms.ToArray();

        int pos = 0;

        // Skip leading whitespace (allowed per spec)
        while (pos < allBytes.Length && IsWhitespace(allBytes[pos]))
            pos++;

        // Read begin marker line
        string beginLine = ReadLine(allBytes, ref pos)
            ?? throw new AgeArmorException("empty armored data");
        if (beginLine != BeginMarker)
            throw new AgeArmorException($"expected begin marker, got: {beginLine}");

        // Read base64 body lines
        var bodyBytes = new List<byte>();
        bool foundEnd = false;
        bool lastBodyLineWasShort = false;

        while (true)
        {
            string? line = ReadLine(allBytes, ref pos);
            if (line == null)
                throw new AgeArmorException("unexpected end of armored data");

            if (line == EndMarker)
            {
                foundEnd = true;
                break;
            }

            // Reject whitespace at start or end of body lines
            if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t' || line[^1] == ' ' || line[^1] == '\t'))
                throw new AgeArmorException("whitespace in armor body line");
            if (line.Length == 0)
                throw new AgeArmorException("empty line in armor body");

            // Lines must not exceed ColumnsPerLine characters
            if (line.Length > ColumnsPerLine)
                throw new AgeArmorException($"armor body line exceeds {ColumnsPerLine} characters");

            // All lines except the last must be exactly ColumnsPerLine characters
            if (lastBodyLineWasShort)
                throw new AgeArmorException("short line in armor body is not the last line");

            if (line.Length < ColumnsPerLine)
                lastBodyLineWasShort = true;

            // Validate and decode base64 (standard padded)
            // Check for line breaks within padding
            if (line.Contains('\r') || line.Contains('\n'))
                throw new AgeArmorException("line break within armor body line");

            // Validate each character is valid base64
            foreach (char c in line)
            {
                if (!IsBase64Char(c))
                    throw new AgeArmorException($"invalid character in armor body: '{c}'");
            }

            // Verify canonical base64: decode and re-encode
            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(line);
            }
            catch (FormatException ex)
            {
                throw new AgeArmorException($"invalid base64 in armor: {ex.Message}");
            }

            // Check canonicality: re-encode and compare
            string reencoded = Convert.ToBase64String(decoded);
            if (reencoded != line)
                throw new AgeArmorException("non-canonical base64 in armor");

            bodyBytes.AddRange(decoded);
        }

        if (!foundEnd)
            throw new AgeArmorException("missing end marker");

        // Skip trailing whitespace (allowed per spec)
        while (pos < allBytes.Length)
        {
            if (!IsWhitespace(allBytes[pos]))
                throw new AgeArmorException("trailing data after end marker");
            pos++;
        }

        return new MemoryStream(bodyBytes.ToArray());
    }

    public static void Armor(Stream input, Stream output)
    {
        using var inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        var data = inputMs.ToArray();

        var writer = new StreamWriter(output, leaveOpen: true) { NewLine = "\n" };
        writer.WriteLine(BeginMarker);

        string b64 = Convert.ToBase64String(data);
        for (int i = 0; i < b64.Length; i += ColumnsPerLine)
        {
            int len = Math.Min(ColumnsPerLine, b64.Length - i);
            writer.Write(b64.AsSpan(i, len));
            writer.WriteLine();
        }

        writer.WriteLine(EndMarker);
        writer.Flush();
    }

    private static string? ReadLine(byte[] data, ref int pos)
    {
        if (pos >= data.Length) return null;
        int start = pos;
        while (pos < data.Length && data[pos] != '\n')
            pos++;
        int end = pos;
        if (pos < data.Length) pos++; // skip the \n

        // Strip trailing \r if present
        if (end > start && data[end - 1] == '\r')
            end--;

        return Encoding.ASCII.GetString(data, start, end - start);
    }

    private static bool IsWhitespace(byte b)
    {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n';
    }

    private static bool IsBase64Char(char c)
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    }
}
