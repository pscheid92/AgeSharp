using System.IO.Pipes;
using System.Text;
using AgeSharp;

namespace Age.Fuzz;

/// <summary>
/// Both sides of the plugin protocol. "plugin" is an <see cref="AgePlugin"/> reading what a
/// client sent (the input's first byte picks the state machine, the rest is its standard
/// input): it must end with one of its exit codes, whatever it reads. "plugin-client" is
/// AgeSharp's client reading what a plugin answered (the first byte picks a recipient, an
/// identity as a recipient, or an identity): it may throw only AgePluginException.
/// </summary>
/// <remarks>
/// The plugin's recipients and identities talk to the user — a message, a confirmation, a
/// value, a secret — so those exchanges are fuzzed too. The seeds are recorded from sessions
/// between the two.
/// </remarks>
internal static class PluginTargets
{
    private const string Name = "fuzz";
    private static readonly byte[] FileKey = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];
    private static readonly X25519Identity Key = X25519Identity.Generate();
    private static readonly X25519Identity OtherKey = X25519Identity.Generate();
    private static readonly AgePlugin Encoder = new(Name);
    private static readonly Lazy<(List<byte[]> Server, List<byte[]> Client)> Recorded = new(Record);

    public static (List<byte[]> Server, List<byte[]> Client) Seeds() => Recorded.Value;

    public static string Server(byte[] data)
    {
        if (data.Length == 0)
            return "empty";
        var stderr = new StringWriter();
        var code = Build().Run([StateMachine(data[0])], new MemoryStream(data, 1, data.Length - 1), new MemoryStream(), stderr);
        if (code is < 0 or > 4)
            throw new Finding("exit code", $"the plugin ended with {code}, not one of its exit codes:\n{stderr}");
        return code == 0 ? "ok" : $"exit {code}: {Outcomes.Words(stderr.ToString())}";
    }

    public static string Client(byte[] data)
    {
        if (data.Length == 0)
            return "empty";
        using var conn = new PluginConnection(new StreamReader(new MemoryStream(data, 1, data.Length - 1), Encoding.ASCII), new StringWriter());
        return Outcomes.Expect<AgePluginException>(() => Talk(data[0] % 3, conn, new Callbacks(confirm: true, secret: "secret")));
    }

    // 0: a recipient wraps; 1: an identity, as a recipient, wraps; 2: an identity unwraps.
    private static void Talk(int kind, PluginConnection conn, IPluginCallbacks callbacks)
    {
        switch (kind)
        {
            case 0:
                PluginRecipient.Parse(Encoder.EncodeRecipient(Encoding.UTF8.GetBytes(Key.Recipient.ToString()!)), callbacks).WrapWithConnection(conn, FileKey);
                break;
            case 1:
                PluginIdentity.Parse(Encoder.EncodeIdentity(Encoding.UTF8.GetBytes(Key.ToSecretString())), callbacks).Recipient.WrapWithConnection(conn, FileKey);
                break;
            default:
                PluginIdentity.Parse(Encoder.EncodeIdentity(Encoding.UTF8.GetBytes(Key.ToSecretString())), callbacks).UnwrapWithConnection(conn, [.. OtherKey.Recipient.Wrap(FileKey), .. Key.Recipient.Wrap(FileKey)]);
                break;
        }
    }

    private static string StateMachine(byte b) => (b & 1) == 0 ? "--age-plugin=recipient-v1" : "--age-plugin=identity-v1";

    // A plugin whose keys carry a native X25519 key, as the interop tests' plugin, and whose
    // recipients and identities talk to the user first.
    private static AgePlugin Build()
    {
        var plugin = new AgePlugin(Name);
        plugin.HandleRecipient(data => new TalkingRecipient(plugin, X25519Recipient.Parse(Encoding.UTF8.GetString(data))));
        plugin.HandleIdentityAsRecipient(data =>
        {
            using var identity = X25519Identity.Parse(Encoding.UTF8.GetString(data));
            return new TalkingRecipient(plugin, identity.Recipient);
        });
        plugin.HandleIdentity(data => new TalkingIdentity(plugin, X25519Identity.Parse(Encoding.UTF8.GetString(data))));
        return plugin;
    }

    private sealed class TalkingRecipient(AgePlugin plugin, IRecipient inner) : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
        {
            plugin.DisplayMessage("wrapping");
            if (plugin.Confirm("go on?", "yes", "no"))
                _ = plugin.RequestValue("a value");
            return inner.Wrap(fileKey);
        }
    }

    private sealed class TalkingIdentity(AgePlugin plugin, IIdentity inner) : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
        {
            _ = plugin.RequestSecret("a secret");
            return inner.TryUnwrap(stanza, fileKey);
        }
    }

    private sealed class Callbacks(bool confirm, string? secret) : IPluginCallbacks
    {
        public void DisplayMessage(string plugin, string message)
        {
        }

        public string? RequestValue(string plugin, string prompt) => "value";

        public char[]? RequestSecret(string plugin, string prompt) => secret?.ToCharArray();

        public bool Confirm(string plugin, string message, string yes, string? no) => confirm;
    }

    // Sessions between the plugin and the client, recorded both ways: what the client sent
    // seeds "plugin", what the plugin answered seeds "plugin-client".
    private static (List<byte[]> Server, List<byte[]> Client) Record()
    {
        var server = new List<byte[]>();
        var client = new List<byte[]>();
        foreach (var kind in new[] { 0, 1, 2 })
        {
            foreach (var callbacks in new[] { new Callbacks(true, "secret"), new Callbacks(false, null) })
            {
                var (sent, answered) = Session(kind == 2 ? "--age-plugin=identity-v1" : "--age-plugin=recipient-v1", conn => Talk(kind, conn, callbacks));
                server.Add([(byte)(kind == 2 ? 1 : 0), .. sent]);
                client.Add([(byte)kind, .. answered]);
            }
        }
        return (server, client);
    }

    private static (byte[] Sent, byte[] Answered) Session(string stateMachine, Action<PluginConnection> talk)
    {
        using var toPlugin = new AnonymousPipeServerStream(PipeDirection.Out);
        using var pluginInput = new AnonymousPipeClientStream(PipeDirection.In, toPlugin.ClientSafePipeHandle);
        using var fromPlugin = new AnonymousPipeServerStream(PipeDirection.In);
        var pluginOutput = new AnonymousPipeClientStream(PipeDirection.Out, fromPlugin.ClientSafePipeHandle);
        var sent = new Recording(toPlugin);
        var answered = new Recording(pluginOutput);

        var server = Task.Factory.StartNew(() =>
        {
            try
            {
                return Build().Run([stateMachine], pluginInput, answered, TextWriter.Null);
            }
            finally
            {
                pluginOutput.Dispose();
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        var conversation = Task.Factory.StartNew(() =>
        {
            try
            {
                using var conn = new PluginConnection(new StreamReader(fromPlugin, Encoding.ASCII), new StreamWriter(sent, Encoding.ASCII));
                talk(conn);
            }
            catch (AgePluginException)
            {
                // A refusal still makes a session worth recording.
            }
            finally
            {
                toPlugin.Dispose();
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        if (!Task.WaitAll([server, conversation], TimeSpan.FromSeconds(30)))
            throw new TimeoutException("a recorded plugin session did not finish");
        return (sent.ToArray(), answered.ToArray());
    }
}
