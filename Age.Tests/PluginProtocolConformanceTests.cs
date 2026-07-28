using Age.Crypto;
using Age.Format;
using Age.Plugin;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// I4 / I5 — protocol conformance against the reference client. The library sends exactly one
/// file, so FILE_INDEX must always be 0 in both directions, a second <c>file-key</c> is an error
/// rather than a replacement, and a <c>confirm</c> must carry its mandatory yes label.
/// </summary>
public class PluginProtocolConformanceTests
{
    private static string MakePluginRecipient(string name)
        => Bech32.Encode($"age1{name}", [0x01, 0x02, 0x03]);

    private static string MakePluginIdentity(string name)
        => Bech32.Encode($"age-plugin-{name}-", [0x01, 0x02, 0x03]).ToUpperInvariant();

    private static string Transcript(Action<PluginConnection> script)
    {
        var output = new StringWriter();
        script(new PluginConnection(new StringReader(""), output));
        return output.ToString();
    }

    private static List<Stanza> OneStanza() => [new("X25519", ["a"], [0x01])];

    [Fact]
    public void RecipientStanzaForAFileWeNeverSent_IsRejected()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("weird"));
        var response = Transcript(c =>
        {
            c.WriteStanza("recipient-stanza", ["7", "weird"], [0x01]);
            c.WriteStanza("done", [], []);
        });

        var conn = new PluginConnection(new StringReader(response), new StringWriter());

        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("unexpected file index", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FileKeyForAPhantomIndex_IsRejected()
    {
        var identity = new PluginIdentity(MakePluginIdentity("weird"));
        var response = Transcript(c =>
        {
            c.WriteStanza("file-key", ["42"], new byte[16]);
            c.WriteStanza("done", [], []);
        });

        var conn = new PluginConnection(new StringReader(response), new StringWriter());

        var ex = Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, OneStanza()));
        Assert.Contains("unexpected file index", ex.Message, StringComparison.Ordinal);
    }

    // Previously the second silently replaced the first, leaving the discarded key material
    // unzeroed on the heap.
    [Fact]
    public void DuplicateFileKey_IsRejectedRatherThanReplacingSilently()
    {
        var identity = new PluginIdentity(MakePluginIdentity("weird"));
        var response = Transcript(c =>
        {
            c.WriteStanza("file-key", ["0"], new byte[16]);
            c.WriteStanza("file-key", ["0"], new byte[16]);
            c.WriteStanza("done", [], []);
        });

        var conn = new PluginConnection(new StringReader(response), new StringWriter());

        var ex = Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, OneStanza()));
        Assert.Contains("duplicate file-key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ConfirmWithNoLabels_IsRejectedInBothPluginTypes()
    {
        var recipientResponse = Transcript(c =>
        {
            c.WriteStanza("confirm", [], "Allow?"u8.ToArray());
            c.WriteStanza("recipient-stanza", ["0", "X25519"], [0x01]);
            c.WriteStanza("done", [], []);
        });

        var recipient = new PluginRecipient(MakePluginRecipient("conf"), new RecordingCallbacks());
        var recipientConn = new PluginConnection(new StringReader(recipientResponse), new StringWriter());
        Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(recipientConn, new byte[16]));

        var identityResponse = Transcript(c =>
        {
            c.WriteStanza("confirm", [], "Allow?"u8.ToArray());
            c.WriteStanza("file-key", ["0"], new byte[16]);
            c.WriteStanza("done", [], []);
        });

        var identity = new PluginIdentity(MakePluginIdentity("conf"), new RecordingCallbacks());
        var identityConn = new PluginConnection(new StringReader(identityResponse), new StringWriter());
        Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(identityConn, OneStanza()));
    }

    // A well-formed confirm still reaches the callback with the plugin's own labels.
    [Fact]
    public void ConfirmWithLabels_StillReachesTheCallback()
    {
        var callbacks = new RecordingCallbacks();
        var recipient = new PluginRecipient(MakePluginRecipient("conf"), callbacks);

        var response = Transcript(c =>
        {
            c.WriteStanza("confirm", [Base64Unpadded.Encode("Touch"u8), Base64Unpadded.Encode("Cancel"u8)],
                "Allow?"u8.ToArray());
            c.WriteStanza("recipient-stanza", ["0", "X25519"], [0x01]);
            c.WriteStanza("done", [], []);
        });

        var conn = new PluginConnection(new StringReader(response), new StringWriter());
        recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Single(callbacks.Confirmations);
        Assert.Equal("Touch", callbacks.Confirmations[0].Yes);
        Assert.Equal("Cancel", callbacks.Confirmations[0].No);
    }

    private sealed class RecordingCallbacks : IPluginCallbacks
    {
        public List<(string Message, string Yes, string? No)> Confirmations { get; } = [];

        public void DisplayMessage(string message) { }

        public string RequestValue(string prompt, bool secret) => "";

        public bool Confirm(string message, string yes, string? no)
        {
            Confirmations.Add((message, yes, no));
            return true;
        }
    }
}
