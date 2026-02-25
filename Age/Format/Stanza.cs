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

        var encoded = Base64Unpadded.Encode(Body);
        var offset = 0;

        while (offset < encoded.Length)
        {
            var len = Math.Min(64, encoded.Length - offset);
            writer.Write(encoded.AsSpan(offset, len));
            writer.Write('\n');
            offset += len;
        }

        // Empty body or exact multiple of 64 chars both need an empty terminator line
        if (encoded.Length % 64 == 0)
            writer.Write('\n');

        writer.Flush();
    }

    internal static Stanza Parse(HeaderReader reader)
    {
        var line = reader.ReadLine()
            ?? throw new AgeHeaderException("unexpected end of header while reading stanza");

        if (!line.StartsWith("-> "))
            throw new AgeHeaderException($"expected stanza prefix '-> ', got: {line}");

        var parts = line[3..].Split(' ');

        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgeHeaderException("stanza must have at least a type");

        var stanzaType = parts[0];
        var stanzaArgs = parts.Length > 1 ? parts[1..] : [];

        // Validate type and args: only printable ASCII (33-126)
        ValidateStanzaString(stanzaType);

        foreach (var arg in stanzaArgs)
            ValidateStanzaString(arg);

        var body = ReadBody(reader);
        return new Stanza(stanzaType, stanzaArgs, body);
    }

    private static byte[] ReadBody(HeaderReader reader)
    {
        var bodyChunks = new List<byte[]>();

        while (true)
        {
            var bodyLine = reader.ReadLine()
                ?? throw new AgeHeaderException("unexpected end of header while reading stanza body");

            if (bodyLine.Length > 64)
                throw new AgeHeaderException("stanza body line exceeds 64 characters");

            if (bodyLine.Length > 0)
                bodyChunks.Add(Base64Unpadded.Decode(bodyLine));

            // A short line (< 64 chars) or empty line terminates the body
            if (bodyLine.Length < 64)
                break;
        }

        return AssembleBody(bodyChunks);
    }

    private static byte[] AssembleBody(List<byte[]> chunks)
    {
        var totalLen = chunks.Sum(c => c.Length);
        var body = new byte[totalLen];
        var pos = 0;

        foreach (var chunk in chunks)
        {
            chunk.CopyTo(body, pos);
            pos += chunk.Length;
        }

        return body;
    }

    private static void ValidateStanzaString(string s)
    {
        if (string.IsNullOrEmpty(s))
            throw new AgeHeaderException("stanza type/argument cannot be empty");

        foreach (var c in s)
        {
            if (c < 33 || c > 126)
                throw new AgeHeaderException($"invalid character in stanza type/argument: 0x{(int)c:X2}");
        }
    }
}
