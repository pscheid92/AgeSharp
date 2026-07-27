using Age.Crypto;
using Age.Plugin;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// C6 / C7 — a plugin binary is a separate process that may be buggy or hostile. Its stderr
/// must not be able to deadlock us, and nothing it sends may surface as a raw BCL exception
/// out of methods documented to throw <see cref="AgePluginException"/>.
/// </summary>
public class PluginRobustnessTests
{
    private static string MakePluginRecipient(string name)
        => Bech32.Encode($"age1{name}", [0x01, 0x02, 0x03]);

    private static PluginConnection Scripted(string pluginOutput)
        => new(new StringReader(pluginOutput), new StringWriter());

    // --- C7: a misbehaving plugin produces AgePluginException, never a raw BCL type ---

    [Fact]
    public void BodyThatIsNotBase64_IsAPluginException()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("bad"));
        var conn = Scripted("-> recipient-stanza 0 bad\n!!!!not base64!!!!\n");

        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("invalid stanza body", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PaddedBody_IsAPluginException()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("bad"));
        var conn = Scripted("-> recipient-stanza 0 bad\nQUFB=\n");

        Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
    }

    // Two consecutive spaces are enough — no exotic bytes required.
    [Fact]
    public void EmptyStanzaArgument_IsAPluginException()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("bad"));
        var conn = Scripted("-> recipient-stanza 0 X25519  extra\nQUFBQQ\n");

        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("empty stanza", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ControlCharacterInStanzaType_IsAPluginException()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("bad"));
        var conn = Scripted("-> recipient-stanza 0 X25519 aaa\nQUFBQQ\n");

        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("invalid character", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MalformedPluginInput_IsAlwaysCatchableAsAgeException()
    {
        // The documented contract: catch (AgeException) is sufficient for callers.
        foreach (var transcript in new[]
                 {
                     "-> recipient-stanza 0 bad\n!!!!\n",
                     "-> recipient-stanza 0 X25519  x\nQUFBQQ\n",
                     "-> recipient-stanza 0 ab\nQUFBQQ\n",
                 })
        {
            var recipient = new PluginRecipient(MakePluginRecipient("bad"));
            var conn = Scripted(transcript);

            var ex = Record.Exception(() => recipient.WrapWithConnection(conn, new byte[16]));

            Assert.NotNull(ex);
            Assert.IsAssignableFrom<AgeException>(ex);
        }
    }
}
