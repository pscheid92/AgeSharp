using Age.Crypto;
using Age.Format;
using Age.Plugin;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// C4 / C5 — a plugin may answer one <c>wrap-file-key</c> with several stanzas (the spec's own
/// recipient-v1 example does exactly that), and on decryption every stanza of one header must be
/// offered under the same FILE_INDEX. Both were wrong: stanzas after the first were silently
/// discarded on encrypt, and on decrypt each was numbered as if it came from a separate file.
/// </summary>
public class PluginMultiStanzaTests
{
    private static string MakePluginRecipient(string name)
        => Bech32.Encode($"age1{name}", [0x01, 0x02, 0x03]);

    private static string MakePluginIdentity(string name)
        => Bech32.Encode($"age-plugin-{name}-", [0x01, 0x02, 0x03]).ToUpperInvariant();

    // Build a plugin transcript by writing it through a connection, so the framing is correct
    // by construction rather than by hand.
    private static string Transcript(Action<PluginConnection> script)
    {
        var output = new StringWriter();
        var writer = new PluginConnection(new StringReader(""), output);
        script(writer);
        return output.ToString();
    }

    private static string TwoStanzaResponse() => Transcript(c =>
    {
        c.WriteStanza("recipient-stanza", ["0", "multi-a"], [0xAA]);
        c.WriteStanza("recipient-stanza", ["0", "multi-b"], [0xBB]);
        c.WriteStanza("done", [], []);
    });

    [Fact]
    public void WrapAll_KeepsEveryStanzaThePluginProduced()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("multi"));
        var conn = new PluginConnection(new StringReader(TwoStanzaResponse()), new StringWriter());

        var stanzas = recipient.WrapAllWithConnection(conn, new byte[16]);

        Assert.Equal(2, stanzas.Count);
        Assert.Equal("multi-a", stanzas[0].Type);
        Assert.Equal("multi-b", stanzas[1].Type);
        Assert.Equal(0xAA, stanzas[0].Body.Span[0]);
        Assert.Equal(0xBB, stanzas[1].Body.Span[0]);
    }

    // A single Stanza cannot represent two, and dropping one destroys the file key beyond
    // recovery — so this must fail loudly rather than succeed silently.
    [Fact]
    public void Wrap_RefusesRatherThanSilentlyDiscarding()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("multi"));
        var conn = new PluginConnection(new StringReader(TwoStanzaResponse()), new StringWriter());

        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("2 recipient stanzas", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Wrap_StillReturnsTheStanzaForASingleStanzaPlugin()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("solo"));
        var response = Transcript(c =>
        {
            c.WriteStanza("recipient-stanza", ["0", "solo-type", "arg1"], [0x01]);
            c.WriteStanza("done", [], []);
        });

        var conn = new PluginConnection(new StringReader(response), new StringWriter());
        var stanza = recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Equal("solo-type", stanza.Type);
        Assert.Equal("arg1", stanza.Args[0]);
    }

    [Fact]
    public void Unwrap_SendsEveryStanzaOfOneHeaderUnderFileIndexZero()
    {
        var identity = new PluginIdentity(MakePluginIdentity("multi"));
        var response = Transcript(c =>
        {
            c.WriteStanza("file-key", ["0"], new byte[16]);
            c.WriteStanza("done", [], []);
        });

        var sentToPlugin = new StringWriter();
        var conn = new PluginConnection(new StringReader(response), sentToPlugin);

        List<Stanza> stanzas =
        [
            new("first", ["a1"], [1, 2, 3]),
            new("second", ["a2"], [4, 5, 6]),
            new("third", ["a3"], [7, 8, 9]),
        ];

        identity.UnwrapWithConnection(conn, stanzas);

        var sent = sentToPlugin.ToString();
        Assert.Contains("-> recipient-stanza 0 first a1", sent, StringComparison.Ordinal);
        Assert.Contains("-> recipient-stanza 0 second a2", sent, StringComparison.Ordinal);
        Assert.Contains("-> recipient-stanza 0 third a3", sent, StringComparison.Ordinal);

        // There is one header here, so nothing may be numbered as a second or third file.
        Assert.DoesNotContain("-> recipient-stanza 1 ", sent, StringComparison.Ordinal);
        Assert.DoesNotContain("-> recipient-stanza 2 ", sent, StringComparison.Ordinal);
    }
}
