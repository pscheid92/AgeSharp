using Age.Crypto;

namespace Age.Format;

/// <summary>
/// One entry in an age file header's recipient list. A stanza carries the
/// wrapped file key for a single recipient, plus recipient-specific metadata.
/// </summary>
/// <remarks>
/// Stanzas are the extensibility primitive used by custom <see cref="Age.Recipients.IRecipient"/>
/// and <see cref="Age.Recipients.IIdentity"/> implementations to communicate
/// wrapped keys through the age wire format. The <paramref name="type"/> tag
/// identifies the recipient kind (<c>"X25519"</c>, <c>"scrypt"</c>, <c>"ssh-ed25519"</c>,
/// <c>"ssh-rsa"</c>, <c>"mlkem768x25519"</c>, or any custom tag).
/// </remarks>
public sealed class Stanza
{
    private readonly string[] _args;
    private readonly byte[] _body;

    /// <summary>
    /// Constructs a stanza with the given type, arguments, and body. The
    /// <paramref name="args"/> and <paramref name="body"/> arrays are
    /// defensively copied; later mutations to the caller's arrays do not
    /// affect this stanza.
    /// </summary>
    /// <param name="type">The recipient type tag (e.g. "X25519"). Must be printable ASCII.</param>
    /// <param name="args">Recipient-specific arguments (e.g. an ephemeral public key). Each argument must be printable ASCII.</param>
    /// <param name="body">The wrapped key material and any recipient-specific binary payload.</param>
    public Stanza(string type, string[] args, byte[] body)
    {
        Type = type;
        _args = (string[])args.Clone();
        _body = (byte[])body.Clone();
    }

    /// <summary>The recipient type tag (e.g. <c>"X25519"</c>, <c>"scrypt"</c>).</summary>
    public string Type { get; }

    /// <summary>Recipient-specific arguments, in the order they appear in the stanza.</summary>
    public IReadOnlyList<string> Args => _args;

    /// <summary>The stanza body — usually the wrapped file key plus any recipient-specific binary payload.</summary>
    public ReadOnlyMemory<byte> Body => _body;

    internal void WriteTo(Stream stream)
    {
        var writer = new StreamWriter(stream, leaveOpen: true) { NewLine = "\n" };
        writer.Write("-> ");
        writer.Write(Type);

        foreach (var arg in _args)
        {
            writer.Write(' ');
            writer.Write(arg);
        }

        writer.Write('\n');
        writer.Flush();

        var encoded = Base64Unpadded.Encode(_body);
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
        var line = reader.ReadLine() ?? throw new AgeHeaderException("unexpected end of header while reading stanza");

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
            var bodyLine = reader.ReadLine() ?? throw new AgeHeaderException("unexpected end of header while reading stanza body");

            switch (bodyLine.Length)
            {
                case > 64:
                    throw new AgeHeaderException("stanza body line exceeds 64 characters");
                case > 0:
                    bodyChunks.Add(Base64Unpadded.Decode(bodyLine));
                    break;
            }

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

        var invalid = s.IndexOfAnyExceptInRange('!', '~');
        if (invalid >= 0)
            throw new AgeHeaderException($"invalid character in stanza type/argument: 0x{(int)s[invalid]:X2}");
    }
}