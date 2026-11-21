using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// Answers what a plugin asks of the user: <c>msg</c>, <c>request-secret</c>,
/// <c>request-public</c> and <c>confirm</c>, the same in the recipient-v1 and identity-v1
/// phases, and <c>unsupported</c> for any other command the phase itself does not handle. Reads
/// the plugin's next command, telling the user when a plugin keeps them waiting.
/// </summary>
internal static class PluginPrompts
{
    /// <summary>How long a plugin may keep the operation waiting before the user is told. go-age's five seconds.</summary>
    internal static TimeSpan WaitingAfter { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The plugin's next command. If it takes longer than <see cref="WaitingAfter"/>, the user is
    /// told the plugin is waiting, once, on another thread, as go-age does.
    /// </summary>
    public static (string Type, string[] Args, byte[] Body) Read(PluginConnection conn, IPluginCallbacks? plugins, string plugin)
    {
        if (plugins is null)
            return conn.ReadNextStanza();

        using var timer = new Timer(_ => Waiting(plugins, plugin), null, WaitingAfter, Timeout.InfiniteTimeSpan);
        return conn.ReadNextStanza();
    }

    // On a timer thread, where an exception would end the process: a host's failure to say the
    // plugin is waiting must not take the operation with it.
    private static void Waiting(IPluginCallbacks plugins, string plugin)
    {
        try
        {
            plugins.Waiting(plugin);
        }
        catch (Exception)
        {
        }
    }

    /// <summary>Answers one command from the plugin.</summary>
    /// <param name="conn">The connection to the plugin.</param>
    /// <param name="plugins">The user interface, or null when there is none.</param>
    /// <param name="plugin">The plugin's name, for the user interface.</param>
    /// <param name="type">The command.</param>
    /// <param name="args">Its arguments.</param>
    /// <param name="body">Its body.</param>
    /// <exception cref="AgePluginException">The command is malformed.</exception>
    public static void Answer(PluginConnection conn, IPluginCallbacks? plugins, string plugin, string type, string[] args, byte[] body)
    {
        switch (type)
        {
            // The spec answers interactive requests with fail when the client has no UI.
            case "msg" or "request-secret" or "request-public" or "confirm" when plugins is null:
                conn.WriteStanza("fail", [], []);
                break;

            case "msg":
                if (Asked(() => plugins!.DisplayMessage(plugin, Encoding.UTF8.GetString(body))))
                    conn.WriteStanza("ok", [], []);
                else
                    conn.WriteStanza("fail", [], []);
                break;

            case "request-public":
                string? value = null;
                if (Asked(() => value = plugins!.RequestValue(plugin, Encoding.UTF8.GetString(body))) && value is not null)
                    conn.WriteStanza("ok", [], Encoding.UTF8.GetBytes(value));
                else
                    conn.WriteStanza("fail", [], []);
                break;

            case "request-secret":
                char[]? secret = null;
                SendSecret(conn, Asked(() => secret = plugins!.RequestSecret(plugin, Encoding.UTF8.GetString(body))) ? secret : null);
                break;

            case "confirm":
                Confirm(conn, plugins!, plugin, args, body);
                break;

            default:
                conn.WriteStanza("unsupported", [], []);
                break;
        }
    }

    // A callback that throws is the user's side failing: the plugin is told, as go-age tells it,
    // and decides what follows.
    private static bool Asked(Action ask)
    {
        try
        {
            ask();
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    // The secret goes to the plugin as UTF-8, and neither the host's array nor the bytes made
    // from it outlive the write.
    private static void SendSecret(PluginConnection conn, char[]? secret)
    {
        if (secret is null)
        {
            conn.WriteStanza("fail", [], []);
            return;
        }

        var utf8 = new byte[Encoding.UTF8.GetByteCount(secret)];

        try
        {
            Encoding.UTF8.GetBytes(secret, utf8);
            conn.WriteStanza("ok", [], utf8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
            Array.Clear(secret);
        }
    }

    private static void Confirm(PluginConnection conn, IPluginCallbacks plugins, string plugin, string[] args, byte[] body)
    {
        // (confirm, Base64(YES_STRING) [Base64(NO_STRING)]; MESSAGE) — the yes label is
        // mandatory, so a missing one is a malformed command, not a label to invent.
        if (args.Length is not (1 or 2))
            throw new AgePluginException("malformed confirm stanza: unexpected number of arguments");

        var message = Encoding.UTF8.GetString(body);
        var yes = DecodeOptionLabel(args[0]);
        var no = args.Length > 1 ? DecodeOptionLabel(args[1]) : null;
        var confirmed = false;

        if (Asked(() => confirmed = plugins.Confirm(plugin, message, yes, no)))
            conn.WriteStanza("ok", [confirmed ? "yes" : "no"], []);
        else
            conn.WriteStanza("fail", [], []);
    }

    private static string DecodeOptionLabel(string arg)
    {
        try
        {
            return Encoding.UTF8.GetString(Base64Unpadded.Decode(arg));
        }
        catch (FormatException)
        {
            throw new AgePluginException($"confirm option label is not valid unpadded base64: {arg}");
        }
    }
}
