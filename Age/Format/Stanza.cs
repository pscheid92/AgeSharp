using Age.Crypto;

namespace Age.Format;

/// <summary>
/// One entry in an age file header's recipient list. A stanza carries the
/// wrapped file key for a single recipient, plus recipient-specific metadata.
/// </summary>
/// <remarks>
/// Stanzas are the extensibility primitive used by custom <see cref="Age.Recipients.IRecipient"/>
/// and <see cref="Age.Recipients.IIdentity"/> implementations to communicate
/// wrapped keys through the age wire format. The <see cref="Type"/> tag
/// identifies the recipient kind (<c>"X25519"</c>, <c>"scrypt"</c>, <c>"ssh-ed25519"</c>,
/// <c>"ssh-rsa"</c>, <c>"mlkem768x25519"</c>, or any custom tag).
/// </remarks>
public sealed class Stanza
{
    private const int ColumnsPerLine = 64;

    private readonly string[] _args;
    private readonly byte[] _body;

    /// <summary>
    /// Writes an encoded body as the spec's <c>*full-line final-line</c> (age.md:132): zero or
    /// more full 64-column lines, then one final line of 0-63 characters.
    /// </summary>
    /// <remarks>
    /// The final line is unconditional, which is what makes an empty body and a body that is an
    /// exact multiple of 64 both terminate with an empty line — no trailing special case.
    /// </remarks>
    internal static void WriteBody(TextWriter writer, ReadOnlySpan<char> encoded)
    {
        while (encoded.Length >= ColumnsPerLine)
        {
            writer.Write(encoded[..ColumnsPerLine]);
            writer.Write('\n');
            encoded = encoded[ColumnsPerLine..];
        }

        writer.Write(encoded);
        writer.Write('\n');
    }

    /// <summary>
    /// Constructs a stanza with the given type, arguments, and body. The
    /// <paramref name="args"/> and <paramref name="body"/> arrays are
    /// defensively copied; later mutations to the caller's arrays do not
    /// affect this stanza.
    /// </summary>
    /// <param name="type">The recipient type tag (e.g. "X25519"). Must be printable ASCII.</param>
    /// <param name="args">Recipient-specific arguments (e.g. an ephemeral public key). Each argument must be printable ASCII.</param>
    /// <param name="body">The wrapped key material and any recipient-specific binary payload.</param>
    /// <exception cref="ArgumentNullException"><paramref name="type"/>, <paramref name="args"/>, or <paramref name="body"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="type"/> or an argument is empty or contains a character outside
    /// printable ASCII (0x21–0x7E) — spaces and newlines would corrupt the header framing.
    /// </exception>
    public Stanza(string type, string[] args, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(body);

        ThrowIfInvalidArgument(type, nameof(type));
        foreach (var arg in args)
            ThrowIfInvalidArgument(arg, nameof(args));

        Type = type;
        _args = [.. args];
        _body = [.. body];
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

        WriteBody(writer, Base64Unpadded.Encode(_body));
        writer.Flush();
    }

    internal static Stanza Parse(HeaderReader reader)
    {
        var line = reader.ReadLine() ?? throw new AgeHeaderException("unexpected end of header while reading stanza");

        if (!line.StartsWith("-> ", StringComparison.Ordinal))
            throw new AgeHeaderException($"expected stanza prefix '-> ', got: {line}");

        var parts = line[3..].Split(' ');

        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgeHeaderException("stanza must have at least a type");

        var stanzaType = parts[0];
        var stanzaArgs = parts.Length > 1 ? parts[1..] : [];

        ThrowIfMalformed(stanzaType);

        foreach (var arg in stanzaArgs)
            ThrowIfMalformed(arg);

        var body = ReadBody(reader);
        return new Stanza(stanzaType, stanzaArgs, body);
    }

    /// <summary>
    /// Reads the <c>*full-line final-line</c> that <see cref="WriteBody"/> writes: full 64-column
    /// lines until one comes up short, which ends the body and may be empty.
    /// </summary>
    private static byte[] ReadBody(HeaderReader reader)
    {
        var chunks = new List<byte[]>();
        string line;

        // The loop condition is the grammar: a full-width line is a full-line, so another line
        // follows it. The first line that is not full width is the final-line and ends the body.
        do
        {
            line = ReadBodyLine(reader);

            if (line.Length > 0)
                chunks.Add(Base64Unpadded.Decode(line));
        }
        while (line.Length == ColumnsPerLine);

        return Concat(chunks);
    }

    /// <summary>
    /// One body line, guaranteed no wider than a full-line — so the caller can read "not full
    /// width" as "final line" without also having to rule out an over-long one.
    /// </summary>
    private static string ReadBodyLine(HeaderReader reader)
    {
        var line = reader.ReadLine()
                   ?? throw new AgeHeaderException("unexpected end of header while reading stanza body");

        return line.Length <= ColumnsPerLine
            ? line
            : throw new AgeHeaderException($"stanza body line exceeds {ColumnsPerLine} characters");
    }

    /// <summary>
    /// Joins the decoded lines into one exactly-sized array.
    /// </summary>
    /// <remarks>
    /// Deliberately not <c>List&lt;byte&gt;</c> or <c>SelectMany().ToArray()</c>, both of which
    /// would be shorter: those grow by reallocating, and every abandoned backing array keeps a
    /// copy of the wrapped file key that nothing can reach to clear. Same reasoning as
    /// <see cref="Age.Crypto.Bech32"/>, which sizes its output exactly for the same reason.
    /// </remarks>
    private static byte[] Concat(List<byte[]> chunks)
    {
        var body = new byte[chunks.Sum(c => c.Length)];
        var pos = 0;

        foreach (var chunk in chunks)
        {
            chunk.CopyTo(body, pos);
            pos += chunk.Length;
        }

        return body;
    }

    /// <summary>
    /// The spec's <c>argument = 1*VCHAR</c> (age.md:130): non-empty printable ASCII. Returns the
    /// index of the first character outside 0x21-0x7E, or -1 if there is none.
    /// </summary>
    /// <remarks>
    /// Shared with <see cref="Age.Plugin.PluginConnection"/>, which applies the same rule to what
    /// a plugin sends. Only the rule is shared — each site words its own message, because they
    /// blame different parties: malformed wire data, a bad argument, or a misbehaving plugin.
    /// </remarks>
    internal static int IndexOfNonVChar(ReadOnlySpan<char> s) =>
        s.IndexOfAnyExceptInRange('!', '~');

    /// <summary>Why a stanza string is unacceptable, or null if it is fine.</summary>
    private static string? InvalidReason(string? s)
    {
        if (string.IsNullOrEmpty(s))
            return "stanza type/argument cannot be empty";

        var invalid = IndexOfNonVChar(s);

        return invalid >= 0
            ? $"invalid character in stanza type/argument: 0x{(int)s[invalid]:X2}"
            : null;
    }

    /// <summary>The string came off the wire, so a bad one means the file is malformed.</summary>
    private static void ThrowIfMalformed(string s)
    {
        if (InvalidReason(s) is { } reason)
            throw new AgeHeaderException(reason);
    }

    /// <summary>The string came from the caller, so a bad one means they passed a bad argument.</summary>
    private static void ThrowIfInvalidArgument(string? s, string paramName)
    {
        if (InvalidReason(s) is { } reason)
            throw new ArgumentException(reason, paramName);
    }
}