using System.Text;
using Age.Crypto;

namespace Age.Plugin;

/// <summary>
/// Answers what a plugin asks of the user: <c>msg</c>, <c>request-secret</c>,
/// <c>request-public</c> and <c>confirm</c>, the same in the recipient-v1 and identity-v1
/// phases, and <c>unsupported</c> for any other command the phase itself does not handle.
/// </summary>
internal static class PluginPrompts
{
    /// <summary>Answers one command from the plugin.</summary>
    /// <param name="conn">The connection to the plugin.</param>
    /// <param name="callbacks">The user interface, or null when there is none.</param>
    /// <param name="type">The command.</param>
    /// <param name="args">Its arguments.</param>
    /// <param name="body">Its body.</param>
    /// <exception cref="AgePluginException">The command is malformed.</exception>
    public static void Answer(PluginConnection conn, IPluginCallbacks? callbacks, string type, string[] args, byte[] body)
    {
        switch (type)
        {
            // The spec answers interactive requests with fail when the client has no UI.
            case "msg" or "request-secret" or "request-public" or "confirm" when callbacks is null:
                conn.WriteStanza("fail", [], []);
                break;

            case "msg":
                callbacks!.DisplayMessage(Encoding.UTF8.GetString(body));
                conn.WriteStanza("ok", [], []);
                break;

            // request-secret masks the input; request-public does not. Same flow otherwise.
            case "request-secret":
            case "request-public":
                var value = callbacks!.RequestValue(Encoding.UTF8.GetString(body), secret: type == "request-secret");
                conn.WriteStanza("ok", [], Encoding.UTF8.GetBytes(value));
                break;

            case "confirm":
                Confirm(conn, callbacks!, args, body);
                break;

            default:
                conn.WriteStanza("unsupported", [], []);
                break;
        }
    }

    private static void Confirm(PluginConnection conn, IPluginCallbacks callbacks, string[] args, byte[] body)
    {
        // (confirm, Base64(YES_STRING) [Base64(NO_STRING)]; MESSAGE) — the yes label is
        // mandatory, so a missing one is a malformed command, not a label to invent.
        if (args.Length is not (1 or 2))
            throw new AgePluginException("malformed confirm stanza: unexpected number of arguments");

        var message = Encoding.UTF8.GetString(body);
        var yes = DecodeOptionLabel(args[0]);
        var no = args.Length > 1 ? DecodeOptionLabel(args[1]) : null;
        var confirmed = callbacks.Confirm(message, yes, no);
        conn.WriteStanza("ok", [confirmed ? "yes" : "no"], []);
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
