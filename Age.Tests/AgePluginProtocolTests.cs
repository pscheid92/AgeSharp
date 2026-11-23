using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// What an <see cref="AgePlugin"/> does with a client that breaks the protocol, scripted stanza by
/// stanza: go-age's checks, exit codes and messages. A malformed request ends the session (1);
/// a key that cannot be used is that key's error (3).
/// </summary>
public class AgePluginProtocolTests
{
    private static readonly byte[] FileKey = new byte[16];

    private static AgePlugin Plugin()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Frood());
        plugin.HandleIdentity(_ => new Frood());
        return plugin;
    }

    private static readonly string Recipient = new AgePlugin("frood").EncodeRecipient([1]);
    private static readonly string Identity = new AgePlugin("frood").EncodeIdentity([1]);

    private static readonly Dictionary<string, (string StateMachine, Action<PluginConnection> Client, int ExitCode, string Stderr)> RequestCases = new()
    {
        // recipient-v1
        ["nothing to wrap to"] = ("recipient-v1", c => c.WriteStanza("done", [], []), 1, "no recipients or identities provided"),
        ["add-recipient without its recipient"] = ("recipient-v1", c => c.WriteStanza("add-recipient", [], []), 1, "add-recipient stanza has 0 arguments, want 1"),
        ["add-recipient with a body"] = ("recipient-v1", c => c.WriteStanza("add-recipient", [Recipient], [1]), 1, "add-recipient stanza has 1 bytes of body, want 0"),
        ["add-identity without its identity"] = ("recipient-v1", c => c.WriteStanza("add-identity", [], []), 1, "add-identity stanza has 0 arguments, want 1"),
        ["extension-labels with an argument"] = ("recipient-v1", c => c.WriteStanza("extension-labels", ["x"], []), 1, "extension-labels stanza has 1 arguments, want 0"),
        ["an empty file key"] = ("recipient-v1", c => c.WriteStanza("wrap-file-key", [], []), 1, "wrap-file-key stanza has 0 bytes of body, want >0"),
        ["done with an argument"] = ("recipient-v1", c => c.WriteStanza("done", ["x"], []), 1, "done stanza has 1 arguments, want 0"),
        ["a client that goes away"] = ("recipient-v1", c => c.WriteStanza("add-recipient", [Recipient], []), 1, "the client went away"),
        ["something that is not a stanza"] = ("recipient-v1", c => c.WriteStanza("add-recipient", [""], []), 1, "client sent an empty stanza argument"),
        ["a stanza answered with fail"] = ("recipient-v1", c => { Request(c, "add-recipient", Recipient); Reply(c, "fail"); }, 1, "expected OK stanza, got \"fail\""),
        ["a stanza answered with a body"] = ("recipient-v1", c => { Request(c, "add-recipient", Recipient); c.WriteStanza("ok", [], [1]); }, 1, "ok stanza has 1 bytes of body, want 0"),
        ["an identity it has no handler for"] = ("recipient-v1", c => { Request(c, "add-identity", Identity); Reply(c, "ok"); }, 3, ""),
        ["a recipient that is not Bech32"] = ("recipient-v1", c => { Request(c, "add-recipient", "frood"); Reply(c, "ok"); }, 3, ""),
        ["an identity in a recipient's place"] = ("recipient-v1", c => { Request(c, "add-recipient", Identity); Reply(c, "ok"); }, 3, ""),
        // identity-v1
        ["no identity"] = ("identity-v1", c => { c.WriteStanza("recipient-stanza", ["0", "frood"], [1]); c.WriteStanza("done", [], []); }, 1, "no identities provided"),
        ["no stanzas"] = ("identity-v1", c => { c.WriteStanza("add-identity", [Identity], []); c.WriteStanza("done", [], []); }, 1, "no stanzas provided"),
        ["a stanza without its type"] = ("identity-v1", c => c.WriteStanza("recipient-stanza", ["0"], []), 1, "recipient-stanza stanza has 1 arguments, want >=2"),
        ["a file index that is not one"] = ("identity-v1", c => c.WriteStanza("recipient-stanza", ["x", "frood"], []), 1, "failed to parse recipient-stanza stanza argument: x"),
        ["a negative file index"] = ("identity-v1", c => c.WriteStanza("recipient-stanza", ["-1", "frood"], []), 1, "failed to parse"),
        ["a recipient in an identity's place"] = ("identity-v1", c => { c.WriteStanza("add-identity", [Recipient], []); c.WriteStanza("recipient-stanza", ["0", "frood"], [1]); c.WriteStanza("done", [], []); Reply(c, "ok"); }, 3, ""),
    };

    public static TheoryData<string> Requests => [.. RequestCases.Keys];

    [Theory]
    [MemberData(nameof(Requests))]
    public void ABrokenRequest_IsRefused(string why)
    {
        var (stateMachine, client, exitCode, stderr) = RequestCases[why];

        var outcome = InProcessPlugin.Run(Plugin(), stateMachine, conn =>
        {
            client(conn);
            return 0;
        });

        Assert.Equal(exitCode, outcome.ExitCode);
        Assert.Contains(stderr, outcome.Stderr);
    }

    // A key it cannot use is that key's error, with go-age's words, and the session ends with 3.
    [Theory]
    [InlineData("add-identity", "identity", "identity encodings not supported")]
    [InlineData("add-recipient", "recipient", "invalid recipient encoding")]
    public void AKeyItCannotUse_IsThatKeysError(string add, string kind, string message)
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Frood());
        var key = add == "add-identity" ? Identity : Bech32Of("age1", [1]);

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            var error = Request(conn, add, key);
            Reply(conn, "ok");
            return error;
        });

        Assert.Equal(3, outcome.ExitCode);
        Assert.Equal("error", outcome.Result.Type);
        Assert.Equal([kind, "0"], outcome.Result.Args);
        Assert.Contains(message, Encoding.UTF8.GetString(outcome.Result.Body));
    }

    [Fact]
    public void AnIdentityPluginWithoutAnIdentityHandler_RefusesIdentityV1()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Frood());

        var outcome = InProcessPlugin.Run(plugin, "identity-v1", conn => conn.ReadStanza());

        Assert.Equal(1, outcome.ExitCode);
        Assert.Contains("identity-v1 not supported", outcome.Stderr);
    }

    // --age-plugin=NAME or --age-plugin NAME, with one dash or two, as Go's flag package reads
    // them; the plugin's own arguments are skipped.
    [Theory]
    [InlineData("--age-plugin identity-v1")]
    [InlineData("-age-plugin=identity-v1")]
    [InlineData("-age-plugin identity-v1")]
    [InlineData("verbose --other --age-plugin=identity-v1")]
    public void TheStateMachine_IsReadAsGoReadsTheFlag(string args)
    {
        var outcome = InProcessPlugin.Run(Plugin(), args.Split(' '), conn =>
        {
            conn.WriteStanza("done", [], []);
            return 0;
        });

        Assert.Contains("no identities provided", outcome.Stderr);
    }

    [Theory]
    [InlineData("")]
    [InlineData("--age-plugin")]
    public void NoStateMachine_IsAnUnknownOne(string args)
    {
        var outcome = InProcessPlugin.Run(Plugin(), args.Split(' ', StringSplitOptions.RemoveEmptyEntries), conn => conn.ReadStanza());

        Assert.Equal(4, outcome.ExitCode);
        Assert.Contains("unknown state machine \"\"", outcome.Stderr);
    }

    // --- Talking to the user ------------------------------------------------------------------

    private static readonly Dictionary<string, (Func<AgePlugin, Action> Ask, Action<PluginConnection> Reply, string Stderr)> ReplyCases = new()
    {
        ["an answer with an argument"] = (p => () => p.DisplayMessage("hi"), c => c.WriteStanza("ok", ["x"], []), "ok stanza has 1 arguments, want 0"),
        ["an answer with a body"] = (p => () => p.DisplayMessage("hi"), c => c.WriteStanza("ok", [], [1]), "ok stanza has 1 bytes of body, want 0"),
        ["a fail with a body"] = (p => () => p.DisplayMessage("hi"), c => c.WriteStanza("fail", [], [1]), "fail stanza has 1 bytes of body, want 0"),
        ["a value with an argument"] = (p => () => p.RequestValue("name?"), c => c.WriteStanza("ok", ["x"], []), "ok stanza has 1 arguments, want 0"),
        ["a secret with an argument"] = (p => () => p.RequestSecret("pin?"), c => c.WriteStanza("ok", ["x"], [1]), "ok stanza has 1 arguments, want 0"),
        ["a confirmation without a choice"] = (p => () => p.Confirm("sure?", "yes"), c => c.WriteStanza("ok", [], []), "ok stanza has 0 arguments, want 1"),
        ["a client that goes away"] = (p => () => p.DisplayMessage("hi"), _ => { }, "the client went away"),
        ["something that is not a stanza"] = (p => () => p.DisplayMessage("hi"), c => c.WriteStanza("ok", [""], []), "client sent an empty stanza argument"),
    };

    // An answer that breaks the protocol ends the session with 2, and nothing more may be asked.
    public static TheoryData<string> BrokenReplies => [.. ReplyCases.Keys];

    [Theory]
    [MemberData(nameof(BrokenReplies))]
    public void ABrokenAnswer_EndsTheSessionWith2(string why)
    {
        var (ask, reply, stderr) = ReplyCases[why];
        var plugin = new AgePlugin("frood");
        Exception? second = null;
        plugin.HandleRecipient(_ => new Asking(() =>
        {
            try
            {
                ask(plugin)();
            }
            catch (AgePluginException)
            {
                second = Record.Exception(() => plugin.DisplayMessage("again"));
            }
        }));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            Request(conn, "add-recipient", Recipient);
            reply(conn);
            return 0;
        });

        Assert.Equal(2, outcome.ExitCode);
        Assert.Contains(stderr, outcome.Stderr);
        Assert.Contains("session is broken", Assert.IsType<AgePluginException>(second).Message);
    }

    // A confirmation with only a yes sends one option; and the client's refusals reach the
    // plugin as exceptions for each kind of request.
    [Fact]
    public void AConfirmationWithOnlyAYes_SendsOneOption()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Asking(() => plugin.Confirm("sure?", "go")));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            var request = Request(conn, "add-recipient", Recipient);
            conn.WriteStanza("ok", ["yes"], []);
            Finish(conn);
            return request;
        });

        Assert.Equal("confirm", outcome.Result.Type);
        Assert.Equal(["Z28"], outcome.Result.Args);
        Assert.Equal(0, outcome.ExitCode);
    }

    [Theory]
    [InlineData("secret", "client failed to request value")]
    [InlineData("confirm", "client failed to request confirmation")]
    public void ARefusal_ReachesThePluginAsAnException(string request, string message)
    {
        var plugin = new AgePlugin("frood");
        Exception? refused = null;
        plugin.HandleRecipient(_ => new Asking(() =>
            refused = Record.Exception(() =>
            {
                if (request == "secret")
                    plugin.RequestSecret("pin?");
                else
                    plugin.Confirm("sure?", "go", "stop");
            })));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            Request(conn, "add-recipient", Recipient);
            Reply(conn, "fail");
            Finish(conn);
            return 0;
        });

        Assert.Equal(0, outcome.ExitCode);
        Assert.Contains(message, Assert.IsType<AgePluginException>(refused).Message);
    }

    // One session at a time: a recipient that starts another is refused, as its key's error.
    [Fact]
    public void ASessionInsideASession_IsRefused()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Asking(() => plugin.Run(["--age-plugin=recipient-v1"])));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            var error = Request(conn, "add-recipient", Recipient);
            Reply(conn, "ok");
            return error;
        });

        Assert.Equal(3, outcome.ExitCode);
        Assert.Contains("already running a session", Encoding.UTF8.GetString(outcome.Result.Body));
    }

    // A recipient that holds something to release is disposed once the session is over.
    [Fact]
    public void ADisposableRecipient_IsDisposedAfterTheSession()
    {
        var recipient = new DisposableFrood();
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => recipient);

        InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            Request(conn, "add-recipient", Recipient);
            Reply(conn, "ok");
            conn.ReadNextStanza();
            return 0;
        });

        Assert.True(recipient.Disposed);
    }

    // A recipient that wraps to nothing would leave a key out of the file, as the client refuses
    // for any recipient: it is that key's error. Null, a default LabelledStanzas, is the same.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ARecipientThatProducesNoStanzas_IsThatKeysError(bool defaultResult)
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => defaultResult ? new DefaultLabelled() : new Empty());

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
            PluginRecipient.Parse(Recipient).WrapWithConnection(conn, FileKey));

        Assert.Equal(3, outcome.ExitCode);
        Assert.Contains("produced no stanzas", Assert.IsType<AgePluginException>(outcome.ClientFailure).Message);
    }

    // An option label must say something: an empty yes is refused before anything is sent, and
    // an empty no is no option at all, as go-age reads it.
    [Fact]
    public void AnEmptyYes_IsRefused()
    {
        var plugin = new AgePlugin("frood");
        Exception? refused = null;
        plugin.HandleRecipient(_ => new Asking(() => refused = Record.Exception(() => plugin.Confirm("sure?", ""))));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            var first = Request(conn, "add-recipient", Recipient);
            Reply(conn, "ok");
            Finish(conn);
            return first;
        });

        Assert.IsType<ArgumentException>(refused);
        Assert.Equal("recipient-stanza", outcome.Result.Type);
    }

    [Fact]
    public void AnEmptyNo_IsNoOption()
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new Asking(() => plugin.Confirm("sure?", "go", "")));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            var request = Request(conn, "add-recipient", Recipient);
            conn.WriteStanza("ok", ["yes"], []);
            Finish(conn);
            return request;
        });

        Assert.Equal(["Z28"], outcome.Result.Args);
        Assert.Equal(0, outcome.ExitCode);
    }

    // However the recipient or identity treats the exception the broken request raised (lets it
    // through, wraps it, or swallows it), the session ends with 2, as go-age's does.
    [Theory]
    [InlineData("recipient-v1", "rethrow")]
    [InlineData("recipient-v1", "wrap")]
    [InlineData("recipient-v1", "swallow")]
    [InlineData("identity-v1", "rethrow")]
    [InlineData("identity-v1", "wrap")]
    [InlineData("identity-v1", "swallow")]
    public void ABrokenSession_EndsWith2_WhateverIsDoneWithTheException(string stateMachine, string handling)
    {
        var plugin = new AgePlugin("frood");
        Action ask = () =>
        {
            try
            {
                plugin.DisplayMessage("hello");
            }
            catch (AgePluginException ex) when (handling != "rethrow")
            {
                if (handling == "wrap")
                    throw new InvalidOperationException("the PIN could not be asked for", ex);
            }
        };
        plugin.HandleRecipient(_ => new Asking(ask));
        plugin.HandleIdentity(_ => new AskingIdentity(ask));

        var outcome = InProcessPlugin.Run(plugin, stateMachine, conn =>
        {
            if (stateMachine == "recipient-v1")
            {
                Request(conn, "add-recipient", Recipient);
            }
            else
            {
                conn.WriteStanza("add-identity", [Identity], []);
                conn.WriteStanza("recipient-stanza", ["0", "frood"], [1]);
                conn.WriteStanza("done", [], []);
                conn.ReadNextStanza();
            }

            conn.WriteStanza("frob", [], []);
            return 0;
        });

        Assert.Equal(2, outcome.ExitCode);
    }

    // Labels go on the wire as stanza arguments, and the protocol forbids duplicates: a recipient
    // whose labels could not be sent as they are is that key's error.
    [Theory]
    [InlineData("a space", "pq frood")]
    [InlineData("a newline", "pq\nfrood")]
    [InlineData("an empty label", "")]
    [InlineData("a duplicate", "pq", "pq")]
    [InlineData("a character outside ASCII", "p\u00e9")]
    [InlineData("a null label", "pq", null)]
    public void ALabelThatCannotBeSent_IsThatKeysError(string why, params string?[] labels)
    {
        _ = why;
        var unescaped = labels.Select(l => l is null ? null : System.Text.RegularExpressions.Regex.Unescape(l)).ToArray();
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => new LabelledFrood(unescaped!));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            var error = Request(conn, "add-recipient", Recipient);
            Reply(conn, "ok");
            return error;
        });

        Assert.Equal(3, outcome.ExitCode);
        Assert.Equal("error", outcome.Result.Type);
        Assert.Contains("label", Encoding.UTF8.GetString(outcome.Result.Body));
    }

    // A client that does not take labels would mix a labelled recipient with any other, which is
    // what labels exist to prevent: as rage's plugins do, that key is refused. One without labels
    // needs no support.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ALabelledRecipient_ForAClientWithoutLabels_IsRefused(bool labelled)
    {
        var plugin = new AgePlugin("frood");
        plugin.HandleRecipient(_ => labelled ? new LabelledFrood(["postquantum"]) : new Frood());

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            conn.WriteStanza("add-recipient", [Recipient], []);
            conn.WriteStanza("wrap-file-key", [], FileKey);
            conn.WriteStanza("done", [], []);
            var reply = conn.ReadNextStanza();
            Reply(conn, "ok");

            if (reply.Type != "error")
                Finish(conn);

            return reply;
        });

        if (labelled)
        {
            Assert.Equal(3, outcome.ExitCode);
            Assert.Equal(["recipient", "0"], outcome.Result.Args);
            Assert.Contains("does not support labels", Encoding.UTF8.GetString(outcome.Result.Body));
        }
        else
        {
            Assert.Equal(0, outcome.ExitCode);
            Assert.Equal("recipient-stanza", outcome.Result.Type);
        }
    }

    // A client that does not know a request answers "unsupported": a refusal the plugin hears as
    // an AgePluginException and can get past, as rage treats it, not a broken session.
    [Fact]
    public void AnUnsupportedRequest_IsARefusal_AndTheSessionGoesOn()
    {
        var plugin = new AgePlugin("frood");
        Exception? refused = null;
        plugin.HandleRecipient(_ => new Asking(() => refused = Record.Exception(() => plugin.Confirm("sure?", "go"))));

        var outcome = InProcessPlugin.Run(plugin, "recipient-v1", conn =>
        {
            Request(conn, "add-recipient", Recipient);
            Reply(conn, "unsupported");
            Finish(conn);
            return 0;
        });

        Assert.Equal(0, outcome.ExitCode);
        Assert.Contains("does not support it", Assert.IsType<AgePluginException>(refused).Message);
    }

    // --- Helpers ------------------------------------------------------------------------------

    // A whole request for one key and a file key, with labels, and the plugin's first reply.
    private static (string Type, string[] Args, byte[] Body) Request(PluginConnection conn, string add, string key)
    {
        conn.WriteStanza(add, [key], []);
        conn.WriteStanza("wrap-file-key", [], FileKey);
        conn.WriteStanza("extension-labels", [], []);
        conn.WriteStanza("done", [], []);

        var reply = conn.ReadNextStanza();

        // Labels come before the stanzas, but after anything the recipient asks while it wraps;
        // acknowledged, they give way to what the test is about.
        if (reply.Type == "labels")
        {
            Reply(conn, "ok");
            reply = conn.ReadNextStanza();
        }

        return reply;
    }

    private static void Reply(PluginConnection conn, string type) => conn.WriteStanza(type, [], []);

    // The rest of the session: every stanza acknowledged, up to the plugin's done.
    private static void Finish(PluginConnection conn)
    {
        for (var reply = conn.ReadNextStanza(); reply.Type != "done"; reply = conn.ReadNextStanza())
            Reply(conn, "ok");
    }

    private static string Bech32Of(string hrp, byte[] data) => AgeSharp.Crypto.Bech32.Encode(hrp, data);

    private sealed class Frood : IRecipient, IIdentity
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => [new Stanza("frood", [], [1])];

        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => false;
    }

    private sealed class Asking(Action ask) : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
        {
            ask();
            return [new Stanza("frood", [], [1])];
        }
    }

    private sealed class AskingIdentity(Action ask) : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
        {
            ask();
            return false;
        }
    }

    private sealed class LabelledFrood(string[] labels) : IRecipientWithLabels
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => WrapWithLabels(fileKey).Stanzas;

        public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) => new([new Stanza("frood", [], [1])], labels);
    }

    private sealed class DisposableFrood : IRecipient, IDisposable
    {
        public bool Disposed { get; private set; }

        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => [new Stanza("frood", [], [1])];

        public void Dispose() => Disposed = true;
    }

    private sealed class Empty : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => [];
    }

    private sealed class DefaultLabelled : IRecipientWithLabels
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => [];

        public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) => default;
    }
}
