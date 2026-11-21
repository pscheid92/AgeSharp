using System.Text;
using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// What a plugin asks of the user reaches the host with the plugin's name, as go-age's ClientUI
/// gets it. Whatever the host cannot answer (declined, or failed) the plugin is told as a
/// failure, and a plugin that keeps the user waiting is said to.
/// </summary>
public class PluginCallbackTests
{
    [Fact]
    public void EveryCallback_IsToldWhichPluginAsks()
    {
        var host = new Host();

        Ask(host, "msg", [], "hello");
        Ask(host, "request-public", [], "name?");
        Ask(host, "request-secret", [], "pin?");
        Ask(host, "confirm", [Base64Unpadded.Encode("Yes"u8)], "sure?");

        Assert.Equal(["yubikey: msg hello", "yubikey: value name?", "yubikey: secret pin?", "yubikey: confirm sure?"], host.Calls);
    }

    [Fact]
    public void ADeclinedValue_IsAFailure()
    {
        var reply = Ask(new Host { Value = null }, "request-public", [], "name?");

        Assert.Equal("fail", reply.Type);
    }

    // As go-age does: the host's side failing is told to the plugin, which decides what follows.
    [Theory]
    [InlineData("msg")]
    [InlineData("request-public")]
    [InlineData("request-secret")]
    [InlineData("confirm")]
    public void ACallbackThatThrows_IsAnsweredWithFail(string command)
    {
        string[] args = command == "confirm" ? [Base64Unpadded.Encode("Yes"u8)] : [];

        var reply = Ask(new Host { Throws = true }, command, args, "anything");

        Assert.Equal("fail", reply.Type);
    }

    [Fact]
    public void AWaitingPlugin_IsSaidToBeWaiting_Once()
    {
        var host = new Host();
        var conn = new PluginConnection(new SlowReader(Reply("done"), until: host.Waited), new StringWriter());
        var before = PluginPrompts.WaitingAfter;

        try
        {
            PluginPrompts.WaitingAfter = TimeSpan.FromMilliseconds(50);
            PluginPrompts.Read(conn, host, "yubikey");
        }
        finally
        {
            PluginPrompts.WaitingAfter = before;
        }

        Assert.True(host.Waited.Wait(TimeSpan.FromSeconds(5)));
        Assert.Equal(["yubikey: waiting"], host.Calls);
    }

    // Unwrapping is where a hardware key waits for its touch.
    [Fact]
    public void AnIdentitysPlugin_IsSaidToBeWaiting_Too()
    {
        var host = new Host();
        var identity = PluginIdentity.Parse(Bech32.Encode("age-plugin-yubikey-", [1, 2, 3]).ToUpperInvariant(), host);
        var conn = new PluginConnection(new SlowReader(Reply("done"), until: host.Waited), new StringWriter());
        var before = PluginPrompts.WaitingAfter;

        try
        {
            PluginPrompts.WaitingAfter = TimeSpan.FromMilliseconds(50);
            Assert.Null(identity.UnwrapWithConnection(conn, [new Stanza("piv-p256", ["a"], [1])]));
        }
        finally
        {
            PluginPrompts.WaitingAfter = before;
        }

        Assert.Equal(["yubikey: waiting"], host.Calls);
    }

    [Fact]
    public void AQuickPlugin_IsNotSaidToBeWaiting()
    {
        var host = new Host();
        var conn = new PluginConnection(new StringReader(Reply("done")), new StringWriter());

        PluginPrompts.Read(conn, host, "yubikey");
        Thread.Sleep(50);

        Assert.Empty(host.Calls);
    }

    // On a timer thread, where an escaping exception ends the process.
    [Fact]
    public void AWaitingNoticeThatThrows_IsContained()
    {
        var host = new Host { Throws = true };
        var conn = new PluginConnection(new SlowReader(Reply("done"), until: host.Waited), new StringWriter());
        var before = PluginPrompts.WaitingAfter;

        try
        {
            PluginPrompts.WaitingAfter = TimeSpan.FromMilliseconds(50);
            var (type, _, _) = PluginPrompts.Read(conn, host, "yubikey");
            Assert.Equal("done", type);
        }
        finally
        {
            PluginPrompts.WaitingAfter = before;
        }

        Assert.True(host.Waited.Wait(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void TheDefaultWaitingNotice_DoesNothing()
    {
        IPluginCallbacks host = new Silent();

        host.Waiting("yubikey");
    }

    [Fact]
    public void WithoutAHost_ReadingIsPlain()
    {
        var conn = new PluginConnection(new StringReader(Reply("done")), new StringWriter());

        Assert.Equal("done", PluginPrompts.Read(conn, null, "yubikey").Type);
    }

    private static (string Type, string[] Args, byte[] Body) Ask(IPluginCallbacks host, string command, string[] args, string body)
    {
        var sent = new StringWriter();
        var conn = new PluginConnection(new StringReader(""), sent);

        PluginPrompts.Answer(conn, host, "yubikey", command, args, Encoding.UTF8.GetBytes(body));

        return new PluginConnection(new StringReader(sent.ToString()), new StringWriter()).ReadNextStanza();
    }

    private static string Reply(string type)
    {
        var text = new StringWriter();
        new PluginConnection(new StringReader(""), text).WriteStanza(type, [], []);
        return text.ToString();
    }

    private sealed class Host : IPluginCallbacks
    {
        public List<string> Calls { get; } = [];
        public string? Value { get; init; } = "value";
        public bool Throws { get; init; }
        public ManualResetEventSlim Waited { get; } = new();

        public void DisplayMessage(string plugin, string message) => Record($"{plugin}: msg {message}");

        public string? RequestValue(string plugin, string prompt)
        {
            Record($"{plugin}: value {prompt}");
            return Value;
        }

        public char[]? RequestSecret(string plugin, string prompt)
        {
            Record($"{plugin}: secret {prompt}");
            return "1234".ToCharArray();
        }

        public bool Confirm(string plugin, string message, string yes, string? no)
        {
            Record($"{plugin}: confirm {message}");
            return true;
        }

        public void Waiting(string plugin)
        {
            Waited.Set();
            Record($"{plugin}: waiting");
        }

        private void Record(string call)
        {
            if (Throws)
                throw new InvalidOperationException("the host failed");

            lock (Calls)
                Calls.Add(call);
        }
    }

    private sealed class Silent : IPluginCallbacks
    {
        public void DisplayMessage(string plugin, string message) { }
        public string? RequestValue(string plugin, string prompt) => null;
        public char[]? RequestSecret(string plugin, string prompt) => null;
        public bool Confirm(string plugin, string message, string yes, string? no) => false;
    }

    // Holds the first line back until the host has been told the plugin is waiting, as a plugin
    // waiting on a touch would: however busy the machine, the notice comes first. Gives up after
    // ten seconds, so a notice that never comes fails the test rather than hanging it.
    private sealed class SlowReader(string text, ManualResetEventSlim until) : TextReader
    {
        private readonly StringReader _inner = new(text);
        private bool _held;

        public override string? ReadLine()
        {
            if (!_held)
            {
                _held = true;
                until.Wait(TimeSpan.FromSeconds(10));
            }

            return _inner.ReadLine();
        }
    }
}
