using Age.Crypto;

namespace Age.Format;

public sealed class Stanza(string type, string[] args, byte[] body)
{
    public string Type => type;
    public string[] Args => args;
    public byte[] Body => body;

    internal void WriteTo(Stream stream)
    {
        var writer = new StreamWriter(stream, leaveOpen: true) { NewLine = "\n" };
        writer.Write("-> ");
        writer.Write(Type);
        foreach (var arg in Args)
        {
            writer.Write(' ');
            writer.Write(arg);
        }
        writer.Write('\n');
        writer.Flush();

        string encoded = Base64Unpadded.Encode(Body);
        int offset = 0;
        while (offset < encoded.Length)
        {
            int len = Math.Min(64, encoded.Length - offset);
            writer.Write(encoded.AsSpan(offset, len));
            writer.Write('\n');
            offset += len;
        }
        // If the body encodes to an exact multiple of 64 chars, we need an empty final line
        if (encoded.Length > 0 && encoded.Length % 64 == 0)
        {
            writer.Write('\n');
        }
        // If body is empty, write an empty line
        if (encoded.Length == 0)
        {
            writer.Write('\n');
        }
        writer.Flush();
    }

    internal static Stanza Parse(HeaderReader reader)
    {
        string line = reader.ReadLine()
            ?? throw new AgeHeaderException("unexpected end of header while reading stanza");

        if (!line.StartsWith("-> "))
            throw new AgeHeaderException($"expected stanza prefix '-> ', got: {line}");

        string rest = line[3..];
        string[] parts = rest.Split(' ');
        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgeHeaderException("stanza must have at least a type");

        string type = parts[0];
        string[] args = parts.Length > 1 ? parts[1..] : [];

        // Validate type and args: only printable ASCII (33-126)
        ValidateStanzaString(type);
        foreach (var arg in args)
            ValidateStanzaString(arg);

        // Read base64 body lines
        var bodyChunks = new List<byte[]>();
        while (true)
        {
            string? bodyLine = reader.ReadLine();
            if (bodyLine == null)
                throw new AgeHeaderException("unexpected end of header while reading stanza body");

            if (bodyLine.Length > 64)
                throw new AgeHeaderException("stanza body line exceeds 64 characters");

            if (bodyLine.Length > 0)
                bodyChunks.Add(Base64Unpadded.Decode(bodyLine));

            // A short line (< 64 chars) or empty line terminates the body
            if (bodyLine.Length < 64)
                break;
        }

        int totalLen = 0;
        foreach (var chunk in bodyChunks) totalLen += chunk.Length;
        var body = new byte[totalLen];
        int pos = 0;
        foreach (var chunk in bodyChunks)
        {
            chunk.CopyTo(body, pos);
            pos += chunk.Length;
        }

        return new Stanza(type, args, body);
    }

    private static void ValidateStanzaString(string s)
    {
        if (string.IsNullOrEmpty(s))
            throw new AgeHeaderException("stanza type/argument cannot be empty");
        foreach (char c in s)
        {
            if (c < 33 || c > 126)
                throw new AgeHeaderException($"invalid character in stanza type/argument: 0x{(int)c:X2}");
        }
    }
}
