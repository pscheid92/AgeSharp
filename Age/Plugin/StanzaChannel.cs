using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// Stanzas over a pair of pipes, as the plugin protocol frames them: read from one side's
/// output, written to the other's input. The client (<see cref="PluginConnection"/>) and the
/// plugin (<see cref="AgePlugin"/>) both speak through one.
/// </summary>
internal sealed class StanzaChannel
{
    private readonly TextReader _reader;
    private readonly Stream? _output;
    private readonly TextWriter? _writer;
    private readonly string _peer;

    /// <param name="reader">The peer's output.</param>
    /// <param name="output">The peer's input, written as bytes.</param>
    /// <param name="peer">Who is at the other end, as errors name it: "plugin" or "client".</param>
    public StanzaChannel(TextReader reader, Stream output, string peer)
    {
        _reader = reader;
        _output = output;
        _peer = peer;
    }

    // The test seam's: text, for tests that script one side.
    public StanzaChannel(TextReader reader, TextWriter writer, string peer)
    {
        _reader = reader;
        _writer = writer;
        _peer = peer;
    }

    /// <summary>Writes one stanza, laid out in buffers that are cleared once it is written.</summary>
    public void Write(string type, string[] args, byte[] body)
    {
        // The whole stanza, laid out as the wire has it, in buffers that are cleared once it is
        // written: the body may be a file key, or a secret the user typed.
        var encodedLength = Base64Unpadded.MaxEncodedLength(body.Length);
        var encoded = ArrayPool<char>.Shared.Rent(encodedLength);
        var line = ArrayPool<byte>.Shared.Rent(StanzaLength(type, args, encodedLength));

        try
        {
            var length = Base64Unpadded.Encode(body, encoded);
            var written = Lay(type, args, encoded.AsSpan(0, length), line);

            if (_output is not null)
            {
                _output.Write(line, 0, written);
                _output.Flush();
            }
            else
            {
                _writer!.Write(Encoding.ASCII.GetString(line, 0, written));
                _writer.Flush();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(encoded.AsSpan()));
            CryptographicOperations.ZeroMemory(line);
            ArrayPool<char>.Shared.Return(encoded);
            ArrayPool<byte>.Shared.Return(line);
        }
    }

    // "-> type args\n", then the body in 64-column lines, the last shorter (empty for a body
    // that fills its lines), each ended by a newline.
    private static int StanzaLength(string type, string[] args, int encodedLength) =>
        3 + type.Length + args.Sum(a => 1 + a.Length) + 1 + encodedLength + encodedLength / Stanza.ColumnsPerLine + 1;

    private static int Lay(string type, string[] args, ReadOnlySpan<char> encoded, Span<byte> into)
    {
        var at = Ascii("-> ", into);
        at += Ascii(type, into[at..]);

        foreach (var arg in args)
        {
            into[at++] = (byte)' ';
            at += Ascii(arg, into[at..]);
        }

        into[at++] = (byte)'\n';

        while (encoded.Length >= Stanza.ColumnsPerLine)
        {
            at += Ascii(encoded[..Stanza.ColumnsPerLine], into[at..]);
            into[at++] = (byte)'\n';
            encoded = encoded[Stanza.ColumnsPerLine..];
        }

        at += Ascii(encoded, into[at..]);
        into[at++] = (byte)'\n';
        return at;
    }

    // Types, arguments and base64 are ASCII by the stanza rules, so a character is a byte.
    private static int Ascii(ReadOnlySpan<char> text, Span<byte> into)
    {
        for (var i = 0; i < text.Length; i++)
            into[i] = (byte)text[i];

        return text.Length;
    }

    /// <summary>The peer's next stanza, or null where its output ends.</summary>
    /// <exception cref="AgePluginException">The peer wrote something that is not a stanza.</exception>
    public (string Type, string[] Args, byte[] Body)? Read()
    {
        var line = _reader.ReadLine();

        if (line == null)
            return null;

        if (!line.StartsWith("-> ", StringComparison.Ordinal))
            throw new AgePluginException($"expected stanza prefix '-> ', got: {line}");

        var parts = line[3..].Split(' ');

        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgePluginException("stanza must have at least a type");

        var stanzaType = parts[0];
        var stanzaArgs = parts.Length > 1 ? parts[1..] : [];

        // Validated here rather than at `new Stanza(...)`, so both plugin types are covered and
        // a malformed stanza is an AgePluginException rather than a raw ArgumentException.
        ThrowIfMalformed(stanzaType, "type", _peer);

        foreach (var arg in stanzaArgs)
            ThrowIfMalformed(arg, "argument", _peer);

        var body = ReadBody();

        return (stanzaType, stanzaArgs, body);
    }

    /// <summary>
    /// The string came from the peer, so a bad one means the peer misbehaved. Same rule
    /// <see cref="Stanza"/> applies to its own input — a space or newline would corrupt the
    /// framing — but worded to name the plugin, since that is who got it wrong here.
    /// </summary>
    private static void ThrowIfMalformed(string s, string what, string peer)
    {
        if (string.IsNullOrEmpty(s))
            throw new AgePluginException($"{peer} sent an empty stanza {what}");

        var invalid = Stanza.IndexOfNonVChar(s);

        if (invalid >= 0)
            throw new AgePluginException(
                $"{peer} sent an invalid character in a stanza {what}: 0x{(int)s[invalid]:X2}");
    }

    private byte[] ReadBody()
    {
        var bodyChunks = new List<byte[]>();

        while (true)
        {
            var bodyLine = _reader.ReadLine() ?? throw new AgePluginException("unexpected end of stream while reading stanza body");

            switch (bodyLine.Length)
            {
                case > 64:
                    throw new AgePluginException("stanza body line exceeds 64 characters");
                case > 0:
                    // Decode throws FormatException for malformed, padded and non-canonical input
                    // alike; the plugin protocol reports all three as AgePluginException.
                    try
                    {
                        bodyChunks.Add(Base64Unpadded.Decode(bodyLine));
                    }
                    catch (FormatException ex)
                    {
                        throw new AgePluginException($"{_peer} sent an invalid stanza body: {ex.Message}", ex);
                    }

                    break;
            }

            if (bodyLine.Length < 64)
                break;
        }

        var totalLen = bodyChunks.Sum(c => c.Length);
        var body = new byte[totalLen];
        var pos = 0;

        foreach (var chunk in bodyChunks)
        {
            chunk.CopyTo(body, pos);
            pos += chunk.Length;
        }

        return body;
    }
}
