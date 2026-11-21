using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A plugin identity's recipient, as go-age's <c>Identity.Recipient</c>: encrypting to it runs the
/// plugin's recipient-v1 with <c>add-identity</c> in place of <c>add-recipient</c>, so a file can
/// be encrypted to the identities in a key file, plugin ones included.
/// </summary>
public class PluginIdentityRecipientTests
{
    private static string MakePluginIdentity(string name) =>
        Bech32.Encode($"age-plugin-{name}-", [0x01, 0x02, 0x03]).ToUpperInvariant();

    [Fact]
    public void APluginIdentity_KnowsItsRecipient()
    {
        var identity = PluginIdentity.Parse(MakePluginIdentity("yubikey"));

        var withRecipient = Assert.IsAssignableFrom<IIdentityWithRecipient>(identity);
        Assert.IsType<PluginRecipient>(withRecipient.Recipient);
        Assert.Equal("yubikey", identity.Recipient.PluginName);
    }

    // The recipient-v1 phase is the usual one, but it names the identity, not a recipient.
    [Fact]
    public void ItsRecipient_SendsTheIdentity_WithAddIdentity()
    {
        var identityString = MakePluginIdentity("yubikey");
        var recipient = PluginIdentity.Parse(identityString).Recipient;

        var (stanzas, sent) = Wrap(recipient, plugin =>
        {
            plugin.WriteStanza("recipient-stanza", ["0", "yubikey", "arg"], [0xAA]);
            plugin.WriteStanza("done", [], []);
        });

        Assert.Equal("yubikey", Assert.Single(stanzas.Stanzas).Type);
        Assert.Contains($"-> add-identity {identityString}\n", sent);
        Assert.DoesNotContain("add-recipient", sent);
        Assert.Contains("-> wrap-file-key", sent);
        Assert.Contains("-> extension-labels", sent);
    }

    [Fact]
    public void ItsRecipient_PassesTheLabelsThePluginDeclares()
    {
        var recipient = PluginIdentity.Parse(MakePluginIdentity("pq")).Recipient;

        var (stanzas, _) = Wrap(recipient, plugin =>
        {
            plugin.WriteStanza("labels", ["postquantum"], []);
            plugin.WriteStanza("recipient-stanza", ["0", "pq"], [0x01]);
            plugin.WriteStanza("done", [], []);
        });

        Assert.Equal(["postquantum"], stanzas.Labels);
    }

    // The identity string may be the key itself, so the recipient never prints it.
    [Fact]
    public void ItsRecipient_DoesNotPrintTheIdentity()
    {
        var identityString = MakePluginIdentity("yubikey");
        var recipient = PluginIdentity.Parse(identityString).Recipient;

        Assert.Equal("PluginRecipient(yubikey, from identity)", recipient.ToString());
        Assert.DoesNotContain(identityString, recipient.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    // The plugin's requests while wrapping reach the callbacks the identity was parsed with.
    [Fact]
    public void ItsRecipient_TalksToTheUserThroughTheIdentitysCallbacks()
    {
        var callbacks = new RecordingCallbacks();
        var recipient = PluginIdentity.Parse(MakePluginIdentity("yubikey"), callbacks).Recipient;

        Wrap(recipient, plugin =>
        {
            plugin.WriteStanza("msg", [], "touch your key"u8.ToArray());
            plugin.WriteStanza("recipient-stanza", ["0", "yubikey"], [0x01]);
            plugin.WriteStanza("done", [], []);
        });

        Assert.Equal([("yubikey", "touch your key")], callbacks.Messages);
    }

    // A no-match error names a plugin identity by its plugin, never by its secret string.
    [Fact]
    public void ANoMatchError_NamesAPluginIdentityByItsPlugin()
    {
        var identityString = MakePluginIdentity("yubikey");
        var stanzas = new[] { new Stanza("X25519", ["arg"], new byte[32]) };

        var ex = IdentityMismatches.For(stanzas, [PluginIdentity.Parse(identityString)]);

        Assert.Equal("PluginIdentity(yubikey)", Assert.Single(ex.Mismatches).Description);
        Assert.DoesNotContain(identityString, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // go-age's age-plugin-batchpass turns its identity into a scrypt recipient: what AgeSharp
    // encrypts to the identity opens with the passphrase, and with the identity through go-age.
    [SkippableFact]
    public void Interop_EncryptToABatchpassIdentity()
    {
        Skip.IfNot(OnPath("age-plugin-batchpass") && AgeCli.Available, "age and age-plugin-batchpass not found on PATH");

        const string passphrase = "batchpass interop";
        var identityString = Bech32.Encode("age-plugin-batchpass-", []).ToUpperInvariant();
        var plaintext = "encrypted to a plugin identity"u8.ToArray();

        Environment.SetEnvironmentVariable("AGE_PASSPHRASE", passphrase);
        Environment.SetEnvironmentVariable("AGE_PASSPHRASE_WORK_FACTOR", "10");

        try
        {
            var identity = PluginIdentity.Parse(identityString);
            var ciphertext = new Recipients(identity.Recipient).Encrypt(plaintext);

            using var scrypt = new AgeSharp.Passphrase(passphrase);
            Assert.Equal(plaintext, new Identities(scrypt).Decrypt(ciphertext));
            Assert.Equal(plaintext, AgeCli.Decrypt(identityString + "\n", ciphertext));
        }
        finally
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", null);
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE_WORK_FACTOR", null);
        }
    }

    // --- Helpers ------------------------------------------------------------------------------

    private static (LabelledStanzas Stanzas, string Sent) Wrap(PluginRecipient recipient, Action<PluginConnection> plugin)
    {
        var replies = new StringWriter();
        plugin(new PluginConnection(new StringReader(""), replies));

        var sent = new StringWriter();
        var conn = new PluginConnection(new StringReader(replies.ToString()), sent);
        return (recipient.WrapWithConnection(conn, new byte[FileKey.Size]), sent.ToString());
    }

    private static bool OnPath(string name) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Any(dir => File.Exists(Path.Combine(dir, name)) || File.Exists(Path.Combine(dir, name + ".exe")));

    private sealed class RecordingCallbacks : IPluginCallbacks
    {
        public List<(string Plugin, string Message)> Messages { get; } = [];

        public void DisplayMessage(string plugin, string message) => Messages.Add((plugin, message));
        public string? RequestValue(string plugin, string prompt) => null;
        public char[]? RequestSecret(string plugin, string prompt) => null;
        public bool Confirm(string plugin, string message, string yes, string? no) => false;
    }
}
