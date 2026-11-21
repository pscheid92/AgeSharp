using System.Text;
using AgeSharp.Crypto;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A plugin asks for a secret (a PIN, a passphrase) with <c>request-secret</c> and for a public
/// value with <c>request-public</c>. The secret comes back from the host as a <c>char[]</c>,
/// because a string cannot be cleared, and the library zeroes it once the plugin has it.
/// </summary>
public class PluginSecretPromptTests
{
    [Fact]
    public void ASecretRequest_GoesToRequestSecret_AndThePluginGetsItsUtf8()
    {
        var callbacks = new Callbacks { Secret = "pïn-€42".ToCharArray() };

        var reply = Ask(callbacks, "request-secret", "Enter PIN:");

        Assert.Equal(["Enter PIN:"], callbacks.SecretPrompts);
        Assert.Empty(callbacks.PublicPrompts);
        Assert.Equal("ok", reply.Type);
        Assert.Equal(Encoding.UTF8.GetBytes("pïn-€42"), reply.Body);
    }

    // The library owns what RequestSecret returned once the plugin has it.
    [Fact]
    public void TheSecretTheHostReturned_IsZeroedOnceSent()
    {
        var secret = "1234".ToCharArray();

        Ask(new Callbacks { Secret = secret }, "request-secret", "Enter PIN:");

        Assert.All(secret, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void APublicRequest_GoesToRequestValue()
    {
        var callbacks = new Callbacks { Value = "user@example.com" };

        var reply = Ask(callbacks, "request-public", "Enter your name:");

        Assert.Equal(["Enter your name:"], callbacks.PublicPrompts);
        Assert.Empty(callbacks.SecretPrompts);
        Assert.Equal("ok", reply.Type);
        Assert.Equal(Encoding.UTF8.GetBytes("user@example.com"), reply.Body);
    }

    // A host that could not get a secret (the user cancelled) answers the way the protocol says
    // a client answers a request it cannot satisfy.
    [Fact]
    public void NoSecretFromTheHost_IsAFail()
    {
        var reply = Ask(new Callbacks { Secret = null }, "request-secret", "Enter PIN:");

        Assert.Equal("fail", reply.Type);
    }

    // The plugin asks, the recipient answers, the plugin produces its stanza. Returns what the
    // recipient sent back to the request.
    private static (string Type, byte[] Body) Ask(IPluginCallbacks callbacks, string request, string prompt)
    {
        var script = new StringWriter();
        var plugin = new PluginConnection(new StringReader(""), script);
        plugin.WriteStanza(request, [], Encoding.UTF8.GetBytes(prompt));
        plugin.WriteStanza("recipient-stanza", ["0", "X25519"], [0x01]);
        plugin.WriteStanza("done", [], []);

        var sent = new StringWriter();
        var recipient = PluginRecipient.Parse(Bech32.Encode("age1test", [0x01, 0x02, 0x03]), callbacks);
        recipient.WrapWithConnection(new PluginConnection(new StringReader(script.ToString()), sent), new byte[16]);

        // What the recipient sent: the add-recipient phase, then its answer to the request.
        var reader = new PluginConnection(new StringReader(sent.ToString()), new StringWriter());

        while (reader.ReadStanza() is { } stanza)
        {
            if (stanza.Type is "ok" or "fail")
                return (stanza.Type, stanza.Body);
        }

        throw new InvalidOperationException("the recipient never answered the request");
    }

    private sealed class Callbacks : IPluginCallbacks
    {
        public char[]? Secret { get; init; }
        public string Value { get; init; } = "";
        public List<string> SecretPrompts { get; } = [];
        public List<string> PublicPrompts { get; } = [];

        public void DisplayMessage(string plugin, string message) { }

        public string? RequestValue(string plugin, string prompt)
        {
            PublicPrompts.Add(prompt);
            return Value;
        }

        public char[]? RequestSecret(string plugin, string prompt)
        {
            SecretPrompts.Add(prompt);
            return Secret!;
        }

        public bool Confirm(string plugin, string message, string yes, string? no) => true;
    }
}
