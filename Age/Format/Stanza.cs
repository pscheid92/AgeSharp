using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     One entry in an age file header's recipient list. A stanza carries the
///     wrapped file key for a single recipient, plus recipient-specific metadata.
/// </summary>
/// <remarks>
///     The extensibility primitive: custom <see cref="IRecipient" /> and
///     <see cref="IIdentity" /> implementations exchange wrapped keys as stanzas, and
///     <see cref="Type" /> is the tag identifying the recipient kind.
/// </remarks>
public sealed class Stanza
{
    private readonly string[] _args;
    private readonly byte[] _body;

    /// <summary>
    ///     <paramref name="args" /> and <paramref name="body" /> are defensively copied, so
    ///     later mutation of the caller's arrays does not affect this stanza.
    /// </summary>
    /// <exception cref="ArgumentNullException">
    ///     <paramref name="type" />, <paramref name="args" />, or <paramref name="body" />
    ///     is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     <paramref name="type" /> or an argument is empty or contains a character outside
    ///     printable ASCII (0x21–0x7E) — spaces and newlines would corrupt the header framing.
    /// </exception>
    public Stanza(string type, string[] args, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(body);

        EnsureValidStanzaString(type, nameof(type));
        foreach (var arg in args)
            EnsureValidStanzaString(arg, nameof(args));

        Type = type;
        _args = (string[])args.Clone();
        _body = (byte[])body.Clone();
    }

    /// <summary>Stanza type of a native age X25519 recipient.</summary>
    public const string X25519 = "X25519";

    /// <summary>Stanza type of a passphrase (scrypt) recipient. Must be a header's only stanza.</summary>
    public const string Scrypt = "scrypt";

    /// <summary>Stanza type of an ssh-ed25519 recipient.</summary>
    public const string SshEd25519 = "ssh-ed25519";

    /// <summary>Stanza type of an ssh-rsa recipient.</summary>
    public const string SshRsa = "ssh-rsa";

    /// <summary>Stanza type of an ML-KEM-768-X25519 (post-quantum) recipient.</summary>
    public const string MlKem768X25519 = "mlkem768x25519";

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
        var line = reader.ReadLine() ?? throw new AgeFormatException("unexpected end of header while reading stanza");

        if (!line.StartsWith("-> "))
            throw new AgeFormatException($"expected stanza prefix '-> ', got: {line}");

        var parts = line[3..].Split(' ');

        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgeFormatException("stanza must have at least a type");

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
            var bodyLine = reader.ReadLine() ??
                           throw new AgeFormatException("unexpected end of header while reading stanza body");

            switch (bodyLine.Length)
            {
                case > 64:
                    throw new AgeFormatException("stanza body line exceeds 64 characters");
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
            throw new AgeFormatException("stanza type/argument cannot be empty");

        var invalid = s.IndexOfAnyExceptInRange('!', '~');
        if (invalid >= 0)
            throw new AgeFormatException($"invalid character in stanza type/argument: 0x{(int)s[invalid]:X2}");
    }

    // Same rule as ValidateStanzaString, but for caller-supplied constructor input,
    // where ArgumentException is the idiomatic failure (the parse path keeps
    // AgeFormatException for malformed wire data).
    private static void EnsureValidStanzaString(string? s, string paramName)
    {
        if (string.IsNullOrEmpty(s))
            throw new ArgumentException("stanza type/argument cannot be empty", paramName);

        var invalid = s.IndexOfAnyExceptInRange('!', '~');
        if (invalid >= 0)
            throw new ArgumentException($"invalid character in stanza type/argument: 0x{(int)s[invalid]:X2}",
                paramName);
    }
}