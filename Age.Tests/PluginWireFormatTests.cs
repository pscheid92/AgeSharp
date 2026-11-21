using System.Text;
using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Stanzas to a plugin are laid out byte by byte, in buffers the connection clears, rather than
/// written through a StreamWriter that keeps the last text it wrote. The bytes are age's stanza
/// format exactly: the command line, then the body in 64-column base64 lines, the last shorter
/// and empty when the body fills its lines.
/// </summary>
public class PluginWireFormatTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(47)]
    [InlineData(48)]
    [InlineData(49)]
    [InlineData(96)]
    [InlineData(1000)]
    public void AStanza_IsWrittenAsTheFormatHasIt(int bodyLength)
    {
        var body = Enumerable.Range(0, bodyLength).Select(i => (byte)(i * 7)).ToArray();
        var sent = new StringWriter();

        new PluginConnection(new StringReader(""), sent).WriteStanza("wrap-file-key", ["a", "bc"], body);

        Assert.Equal(Expected("wrap-file-key", ["a", "bc"], body), sent.ToString());
    }

    [Fact]
    public void AStanzaWithoutArguments_HasNone()
    {
        var sent = new StringWriter();

        new PluginConnection(new StringReader(""), sent).WriteStanza("done", [], []);

        Assert.Equal("-> done\n\n", sent.ToString());
    }

    // What is written reads back as what was written.
    [Fact]
    public void AStanza_ReadsBack()
    {
        var body = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();
        var sent = new StringWriter();
        new PluginConnection(new StringReader(""), sent).WriteStanza("recipient-stanza", ["0", "X25519", "arg"], body);

        var (type, args, read) = new PluginConnection(new StringReader(sent.ToString()), new StringWriter()).ReadNextStanza();

        Assert.Equal("recipient-stanza", type);
        Assert.Equal(["0", "X25519", "arg"], args);
        Assert.Equal(body, read);
    }

    private static string Expected(string type, string[] args, byte[] body)
    {
        var text = new StringBuilder("-> ").Append(type);
        foreach (var arg in args)
            text.Append(' ').Append(arg);
        text.Append('\n');

        var encoded = Convert.ToBase64String(body).TrimEnd('=');
        for (var at = 0; at <= encoded.Length; at += 64)
        {
            var rest = encoded.Length - at;
            text.Append(encoded, at, Math.Min(64, rest)).Append('\n');

            if (rest < 64)
                break;
        }

        return text.ToString();
    }
}
