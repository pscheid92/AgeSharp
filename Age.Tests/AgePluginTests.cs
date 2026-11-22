using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The plugin side of the protocol: an <see cref="AgePlugin"/> exposes ordinary recipients and
/// identities as an <c>age-plugin-*</c> binary, and AgeSharp's own client talks to it here over
/// pipes, as it would to a process. The plugin in most tests carries a native X25519 key in its
/// Bech32 data: recipients <c>age1frood1…</c> wrap to it, identities <c>AGE-PLUGIN-FROOD-1…</c>
/// unwrap with it.
/// </summary>
public class AgePluginTests
{
    private static readonly byte[] FileKey = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

    // --- Keys ---------------------------------------------------------------------------------

    [Fact]
    public void ItEncodesKeysForItsName_AsTheClientParsesThem()
    {
        var plugin = new AgePlugin("Frood");

        var recipient = plugin.EncodeRecipient([1, 2, 3]);
        var identity = plugin.EncodeIdentity([1, 2, 3]);

        Assert.Equal("frood", plugin.Name);
        Assert.StartsWith("age1frood1", recipient);
        Assert.StartsWith("AGE-PLUGIN-FROOD-1", identity);
        Assert.Equal("frood", PluginRecipient.Parse(recipient).PluginName);
        Assert.Equal("frood", PluginIdentity.Parse(identity).PluginName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("fro od")]
    [InlineData("../frood")]
    [InlineData("frood\\x")]
    public void AnInvalidName_IsRefused(string name)
    {
        Assert.Throws<ArgumentException>(() => new AgePlugin(name));
    }

    [Fact]
    public void EachHandler_IsRegisteredOnce()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => throw new NotImplementedException());
        plugin.HandleIdentity(_ => throw new NotImplementedException());
        plugin.HandleIdentityAsRecipient(_ => throw new NotImplementedException());

        Assert.Throws<InvalidOperationException>(() => plugin.HandleRecipient(_ => throw new NotImplementedException()));
        Assert.Throws<InvalidOperationException>(() => plugin.HandleIdentity(_ => throw new NotImplementedException()));
        Assert.Throws<InvalidOperationException>(() => plugin.HandleIdentityAsRecipient(_ => throw new NotImplementedException()));
    }

    // --- recipient-v1 and identity-v1 ---------------------------------------------------------

    [Fact]
    public void WhatItsRecipientWraps_ItsIdentityUnwraps()
    {
        using var key = X25519Identity.Generate();
        var plugin = FroodPlugin();

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient(Utf8(key.Recipient.ToString()))));
        var unwrapped = Unwrap(plugin, PluginIdentity.Parse(plugin.EncodeIdentity(Utf8(key.ToSecretString()))), wrapped.Result!.Stanzas);

        Assert.Equal(0, wrapped.ExitCode);
        Assert.Equal("X25519", Assert.Single(wrapped.Result.Stanzas).Type);
        Assert.Equal(0, unwrapped.ExitCode);
        Assert.Equal(FileKey, unwrapped.Result);
    }

    // An identity's recipient is sent as add-identity, which HandleIdentityAsRecipient answers.
    [Fact]
    public void AnIdentitysRecipient_WrapsThroughHandleIdentityAsRecipient()
    {
        using var key = X25519Identity.Generate();
        var plugin = FroodPlugin();
        var identity = PluginIdentity.Parse(plugin.EncodeIdentity(Utf8(key.ToSecretString())));

        var wrapped = Wrap(plugin, identity.Recipient);
        var unwrapped = Unwrap(plugin, identity, wrapped.Result!.Stanzas);

        Assert.Equal(FileKey, unwrapped.Result);
    }

    [Fact]
    public void ARecipientsLabels_ReachTheClient()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Labelled(["postquantum", "frood"]));

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1])));

        Assert.Equal(["postquantum", "frood"], wrapped.Result!.Labels);
    }

    [Fact]
    public void AnUnlabelledRecipient_HasNoLabels()
    {
        using var key = X25519Identity.Generate();
        var plugin = FroodPlugin();

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient(Utf8(key.Recipient.ToString()))));

        Assert.Empty(wrapped.Result!.Labels);
    }

    [Fact]
    public void EveryStanzaARecipientProduces_IsSent()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Several(3));

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1])));

        Assert.Equal(["a0", "a1", "a2"], wrapped.Result!.Stanzas.Select(s => s.Args[0]));
    }

    // Not this identity's file: the plugin finishes without a file key, and that is no error.
    [Fact]
    public void AnIdentityThatDeclines_EndsWithoutAFileKey()
    {
        using var key = X25519Identity.Generate();
        using var someoneElse = X25519Identity.Generate();
        var plugin = FroodPlugin();
        var stanzas = someoneElse.Recipient.Wrap(FileKey);

        var unwrapped = Unwrap(plugin, PluginIdentity.Parse(plugin.EncodeIdentity(Utf8(key.ToSecretString()))), stanzas);

        Assert.Equal(0, unwrapped.ExitCode);
        Assert.Null(unwrapped.Result);
        Assert.Null(unwrapped.ClientFailure);
    }

    // --- Talking to the user ------------------------------------------------------------------

    [Fact]
    public void DuringAWrap_ThePluginTalksToTheUserThroughTheClient()
    {
        var plugin = new AgePlugin("frood");
        string? value = null, secret = null;
        bool? confirmed = null;
        plugin.HandleRecipient(_ => new Interactive(() =>
        {
            plugin.DisplayMessage("touch your frood");
            value = plugin.RequestValue("name?");
            secret = new string(plugin.RequestSecret("pin?"));
            confirmed = plugin.Confirm("really?", "yes please", "no thanks");
        }));
        var callbacks = new Callbacks();

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1]), callbacks));

        Assert.Equal(0, wrapped.ExitCode);
        Assert.Equal(["frood: touch your frood"], callbacks.Messages);
        Assert.Equal("arthur", value);
        Assert.Equal("1234", secret);
        Assert.True(confirmed);
        Assert.Equal(("really?", "yes please", "no thanks"), callbacks.Confirmed);
    }

    // A client with no way to reach the user fails each request; the plugin hears it as an
    // AgePluginException, which, uncaught, becomes the plugin's error.
    [Fact]
    public void AClientThatCannotAsk_FailsTheRequest()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Interactive(() => plugin.RequestValue("name?")));

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1])));

        Assert.Equal(3, wrapped.ExitCode);
        var ex = Assert.IsType<AgePluginException>(wrapped.ClientFailure);
        Assert.Contains("client failed to request value", ex.Message);
    }

    [Fact]
    public void TalkingToTheUser_OutsideAWrapOrUnwrap_IsRefused()
    {
        var plugin = new AgePlugin("frood");

        Assert.Throws<InvalidOperationException>(() => plugin.DisplayMessage("hello"));
    }

    // --- Errors -------------------------------------------------------------------------------

    [Fact]
    public void ARecipientThePluginCannotParse_IsReportedAsItsError()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => throw new FormatException("not a frood key"));

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1])));

        Assert.Equal(3, wrapped.ExitCode);
        Assert.Contains("not a frood key", Assert.IsType<AgePluginException>(wrapped.ClientFailure).Message);
    }

    [Fact]
    public void ARecipientForAnotherPlugin_IsRefused()
    {
        var plugin = FroodPlugin();
        var other = new AgePlugin("other").EncodeRecipient([1]);

        var wrapped = InProcessPlugin.Run(plugin, "recipient-v1", conn => PluginRecipient.Parse(other).WrapWithConnection(conn, FileKey));

        Assert.Equal(3, wrapped.ExitCode);
        Assert.Contains("unsupported plugin name", Assert.IsType<AgePluginException>(wrapped.ClientFailure).Message);
    }

    [Fact]
    public void AWrapThatFails_IsReportedAsTheRecipientsError()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Interactive(() => throw new InvalidOperationException("frood unplugged")));

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1])));

        Assert.Equal(3, wrapped.ExitCode);
        Assert.Contains("frood unplugged", Assert.IsType<AgePluginException>(wrapped.ClientFailure).Message);
    }

    // Recipients must agree on their labels, as they must in a file.
    [Fact]
    public void RecipientsWithDifferentLabels_AreRefused()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(data => new Labelled(data[0] == 1 ? ["postquantum"] : []));

        var wrapped = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            conn.WriteStanza("add-recipient", [plugin.EncodeRecipient([1])], []);
            conn.WriteStanza("add-recipient", [plugin.EncodeRecipient([2])], []);
            conn.WriteStanza("wrap-file-key", [], FileKey);
            conn.WriteStanza("extension-labels", [], []);
            conn.WriteStanza("done", [], []);
            var error = conn.ReadNextStanza();
            conn.WriteStanza("ok", [], []);
            return error;
        });

        Assert.Equal(3, wrapped.ExitCode);
        Assert.Equal("error", wrapped.Result.Type);
        Assert.Equal(["recipient", "1"], wrapped.Result.Args);
        Assert.Contains("labels", Encoding.UTF8.GetString(wrapped.Result.Body));
    }

    [Fact]
    public void AnUnwrapThatFails_IsReportedAsAStanzaError()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleIdentity(_ => new Failing("frood unplugged"));

        var unwrapped = Unwrap(plugin, PluginIdentity.Parse(plugin.EncodeIdentity([1])), [new Stanza("frood", [], [1])]);

        Assert.Contains("frood unplugged", Assert.IsType<AgePluginException>(unwrapped.ClientFailure).Message);
    }

    [Fact]
    public void AStateMachineWithoutAHandler_IsAFatalError()
    {
        var plugin = new AgePlugin("frood");

        var wrapped = InProcessPlugin.Run(plugin, "recipient-v1", conn => conn.ReadStanza());

        Assert.Equal(1, wrapped.ExitCode);
        Assert.Contains("recipient-v1 not supported", wrapped.Stderr);
    }

    [Fact]
    public void AnUnknownStateMachine_ExitsWith4()
    {
        var plugin = FroodPlugin();

        var outcome = InProcessPlugin.Run(plugin, "frood-v9", conn => conn.ReadStanza());

        Assert.Equal(4, outcome.ExitCode);
        Assert.Contains("unknown state machine", outcome.Stderr);
    }

    [Fact]
    public void ARequestWithoutAFileKey_IsAFatalError()
    {
        var plugin = FroodPlugin();

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            conn.WriteStanza("add-recipient", [plugin.EncodeRecipient([1])], []);
            conn.WriteStanza("done", [], []);
            return conn.ReadStanza();
        });

        Assert.Equal(1, outcome.ExitCode);
        Assert.Contains("no file keys", outcome.Stderr);
    }

    // A client that answers a request with neither ok nor fail has broken the session: the
    // plugin ends it with exit code 2, whatever the recipient does with the exception.
    [Fact]
    public void AClientThatBreaksTheProtocolMidRequest_EndsTheSessionWith2()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Interactive(() =>
        {
            try
            {
                plugin.DisplayMessage("hello");
            }
            catch (AgePluginException)
            {
                // Swallowed: the session is broken all the same.
            }
        }));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            conn.WriteStanza("add-recipient", [plugin.EncodeRecipient([1])], []);
            conn.WriteStanza("wrap-file-key", [], FileKey);
            conn.WriteStanza("done", [], []);
            var request = conn.ReadNextStanza();
            conn.WriteStanza("frob", [], []);
            return request;
        });

        Assert.Equal("msg", outcome.Result.Type);
        Assert.Equal(2, outcome.ExitCode);
        Assert.Contains("expected ok or fail", outcome.Stderr);
    }

    // The same during an unwrap: an identity that swallows the broken request and declines still
    // ends the session with exit code 2.
    [Fact]
    public void AClientThatBreaksTheProtocolDuringAnUnwrap_EndsTheSessionWith2()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleIdentity(_ => new Asking(plugin));

        var outcome = InProcessPlugin.Run(plugin, "identity-v1", conn =>
        {
            conn.WriteStanza("add-identity", [plugin.EncodeIdentity([1])], []);
            conn.WriteStanza("recipient-stanza", ["0", "frood"], [1]);
            conn.WriteStanza("done", [], []);
            var request = conn.ReadNextStanza();
            conn.WriteStanza("frob", [], []);
            return request;
        });

        Assert.Equal("msg", outcome.Result.Type);
        Assert.Equal(2, outcome.ExitCode);
    }

    // Stanzas the plugin does not know are ignored while the client sends its request, as the
    // protocol requires (clients send them to test that plugins do).
    [Fact]
    public void AnUnknownStanzaInTheRequest_IsIgnored()
    {
        using var key = X25519Identity.Generate();
        var plugin = FroodPlugin();

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            conn.WriteStanza("grease-frood", ["x"], [1, 2]);
            conn.WriteStanza("add-recipient", [plugin.EncodeRecipient(Utf8(key.Recipient.ToString()))], []);
            conn.WriteStanza("wrap-file-key", [], FileKey);
            conn.WriteStanza("done", [], []);
            var stanza = conn.ReadNextStanza();
            conn.WriteStanza("ok", [], []);
            return (stanza, conn.ReadNextStanza());
        });

        Assert.Equal(0, outcome.ExitCode);
        Assert.Equal("recipient-stanza", outcome.Result.stanza.Type);
        Assert.Equal("done", outcome.Result.Item2.Type);
    }

    // One session may carry several files, each with any number of stanzas. Each is answered with
    // its own index, and a file whose unwrap fails is that file's error: the session goes on.
    [Fact]
    public void SeveralFiles_AreAnsweredEachByItsIndex_AndAFailureEndsOnlyItsFile()
    {
        using var key = X25519Identity.Generate();
        var plugin = new AgePlugin("frood");
        plugin.HandleIdentity(data => new FailingOn("broken", X25519Identity.Parse(Encoding.UTF8.GetString(data))));
        var good = Assert.Single(key.Recipient.Wrap(FileKey));

        var outcome = InProcessPlugin.Run(plugin, "identity-v1", conn =>
        {
            conn.WriteStanza("add-identity", [plugin.EncodeIdentity(Utf8(key.ToSecretString()))], []);
            conn.WriteStanza("recipient-stanza", ["0", "broken"], [1]);
            conn.WriteStanza("recipient-stanza", ["1", "frood"], [1]);
            conn.WriteStanza("recipient-stanza", ["1", good.Type, .. good.Args], good.Body.ToArray());
            conn.WriteStanza("done", [], []);

            var replies = new List<(string Type, string[] Args, byte[] Body)>();

            while (true)
            {
                var reply = conn.ReadNextStanza();
                replies.Add(reply);

                if (reply.Type == "done")
                    return replies;

                conn.WriteStanza("ok", [], []);
            }
        });

        var replies = Assert.IsType<List<(string Type, string[] Args, byte[] Body)>>(outcome.Result);
        Assert.Equal(0, outcome.ExitCode);
        Assert.Equal(["error", "file-key", "done"], replies.Select(r => r.Type));
        Assert.Equal(["stanza", "0", "0"], replies[0].Args);
        Assert.Equal(["1"], replies[1].Args);
        Assert.Equal(FileKey, replies[1].Body);
    }

    // A client may send several file keys; each recipient's stanzas come back under the index of
    // the file key they wrap.
    [Fact]
    public void SeveralFileKeys_AreWrappedEachUnderItsIndex()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Labelled([]));
        byte[] second = [.. FileKey.Reverse()];

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            conn.WriteStanza("add-recipient", [plugin.EncodeRecipient([1])], []);
            conn.WriteStanza("wrap-file-key", [], FileKey);
            conn.WriteStanza("wrap-file-key", [], second);
            conn.WriteStanza("done", [], []);

            var replies = new List<(string Type, string[] Args, byte[] Body)>();

            for (var reply = conn.ReadNextStanza(); reply.Type != "done"; reply = conn.ReadNextStanza())
            {
                replies.Add(reply);
                conn.WriteStanza("ok", [], []);
            }

            return replies;
        });

        var replies = Assert.IsType<List<(string Type, string[] Args, byte[] Body)>>(outcome.Result);
        Assert.Equal(0, outcome.ExitCode);
        Assert.Equal([["0", "frood"], ["1", "frood"]], replies.Select(r => r.Args));
        Assert.Equal([FileKey, second], replies.Select(r => r.Body));
    }

    // A handler only makes the key: talking to the user is for its Wrap or TryUnwrap.
    [Fact]
    public void AHandlerThatTalksToTheUser_IsRefused()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ =>
        {
            plugin.DisplayMessage("parsing");
            return new Labelled([]);
        });

        var wrapped = Wrap(plugin, PluginRecipient.Parse(plugin.EncodeRecipient([1]), new Callbacks()));

        Assert.Equal(3, wrapped.ExitCode);
        Assert.Contains("only from a recipient's Wrap", Assert.IsType<AgePluginException>(wrapped.ClientFailure).Message);
    }

    [Fact]
    public void StanzasForAFileOutOfOrder_AreAFatalError()
    {
        var plugin = FroodPlugin();

        var outcome = InProcessPlugin.Run(plugin, "identity-v1", conn =>
        {
            conn.WriteStanza("add-identity", [plugin.EncodeIdentity([1])], []);
            conn.WriteStanza("recipient-stanza", ["1", "frood"], [1]);
            conn.WriteStanza("done", [], []);
            return conn.ReadStanza();
        });

        Assert.Equal(1, outcome.ExitCode);
        Assert.Contains("unexpected file index 1", outcome.Stderr);
    }

    // The identities a handler made are the plugin's to dispose once the session is over.
    [Fact]
    public void TheIdentitiesItParsed_AreDisposedAfterTheSession()
    {
        using var key = X25519Identity.Generate();
        var plugin = new AgePlugin("frood");
        var parsed = new List<X25519Identity>();
        plugin.HandleIdentity(data =>
        {
            var identity = X25519Identity.Parse(Encoding.UTF8.GetString(data));
            parsed.Add(identity);
            return identity;
        });

        Unwrap(plugin, PluginIdentity.Parse(plugin.EncodeIdentity(Utf8(key.ToSecretString()))), key.Recipient.Wrap(FileKey));

        Assert.Equal("X25519Identity(disposed)", Assert.Single(parsed).ToString());
    }

    // --- Helpers ------------------------------------------------------------------------------

    private static AgePlugin FroodPlugin()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(data => X25519Recipient.Parse(Encoding.UTF8.GetString(data)));
        plugin.HandleIdentity(data => X25519Identity.Parse(Encoding.UTF8.GetString(data)));
        plugin.HandleIdentityAsRecipient(data => X25519Identity.Parse(Encoding.UTF8.GetString(data)).Recipient);
        return plugin;
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static InProcessPlugin.Outcome<LabelledStanzas> Wrap(AgePlugin plugin, PluginRecipient recipient) =>
        InProcessPlugin.Run(plugin, "recipient-v1", conn => recipient.WrapWithConnection(conn, FileKey));

    private static InProcessPlugin.Outcome<byte[]?> Unwrap(AgePlugin plugin, PluginIdentity identity, IReadOnlyList<Stanza> stanzas) =>
        InProcessPlugin.Run(plugin, "identity-v1", conn => identity.UnwrapWithConnection(conn, stanzas));

    private sealed class Labelled(string[] labels) : IRecipientWithLabels
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => WrapWithLabels(fileKey).Stanzas;

        public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) => new([new Stanza("frood", [], fileKey.ToArray())], labels);
    }

    private sealed class Several(int count) : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) =>
            [.. Enumerable.Range(0, count).Select(i => new Stanza("frood", [$"a{i}"], [1]))];
    }

    private sealed class Interactive(Action interact) : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
        {
            interact();
            return [new Stanza("frood", [], [1])];
        }
    }

    private sealed class Failing(string message) : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => throw new InvalidOperationException(message);
    }

    // Asks the user something, swallows whatever goes wrong, and declines.
    private sealed class Asking(AgePlugin plugin) : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
        {
            try
            {
                plugin.DisplayMessage("hello");
            }
            catch (AgePluginException)
            {
                // Swallowed: the session is broken all the same.
            }

            return false;
        }
    }

    // Fails on a stanza of one type, and otherwise is the X25519 identity it wraps.
    private sealed class FailingOn(string type, X25519Identity inner) : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) =>
            stanza.Type == type ? throw new InvalidOperationException("frood unplugged") : inner.TryUnwrap(stanza, fileKey);

        public void Dispose() => inner.Dispose();
    }

    private sealed class Callbacks : IPluginCallbacks
    {
        public List<string> Messages { get; } = [];
        public (string, string, string?)? Confirmed { get; private set; }

        public void DisplayMessage(string plugin, string message) => Messages.Add($"{plugin}: {message}");
        public string? RequestValue(string plugin, string prompt) => "arthur";
        public char[]? RequestSecret(string plugin, string prompt) => "1234".ToCharArray();

        public bool Confirm(string plugin, string message, string yes, string? no)
        {
            Confirmed = (message, yes, no);
            return true;
        }
    }
}
