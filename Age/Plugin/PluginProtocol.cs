using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

// The part of the age-plugin client protocol that recipient-v1 and identity-v1 share:
// reading the next stanza, and the interactive stanzas (msg, request-secret,
// request-public, confirm) that either side may receive at any point.
internal static class PluginProtocol
{
    public static (string Type, string[] Args, byte[] Body) ReadStanza(PluginConnection conn) =>
        conn.ReadStanza() ?? throw new AgePluginException("unexpected end of plugin output");

    public static void HandleCommonStanza(PluginConnection conn, IPluginCallbacks? callbacks,
                                          string type, string[] args, byte[] body)
    {
        switch (type)
        {
            // The spec answers interactive requests with fail when there is no UI to present them.
            case "msg" or "request-secret" or "request-public" or "confirm" when callbacks is null:
                conn.WriteStanza("fail", [], []);
                break;

            case "msg":
                callbacks!.DisplayMessage(Encoding.UTF8.GetString(body));
                conn.WriteStanza("ok", [], []);
                break;

            case "request-secret":
            case "request-public":
                var value = callbacks!.RequestValue(Encoding.UTF8.GetString(body), type == "request-secret");
                conn.WriteStanza("ok", [], Encoding.UTF8.GetBytes(value));
                break;

            case "confirm":
                HandleConfirm(conn, callbacks!, args, body);
                break;

            default:
                conn.WriteStanza("unsupported", [], []);
                break;
        }
    }

    // The plugin name reaches Process.Start as age-plugin-<name>, so it is validated here.
    public static string ExtractPluginName(string s, string prefix, string suffix, string what)
    {
        var (hrp, _) = Bech32.Decode(s);

        if (!hrp.StartsWith(prefix, StringComparison.Ordinal) ||
            !hrp.EndsWith(suffix, StringComparison.Ordinal) ||
            hrp.Length <= prefix.Length + suffix.Length)
            throw new AgeFormatException($"invalid plugin {what} HRP: {hrp}");

        return PluginNameValidator.Validate(hrp[prefix.Length..(hrp.Length - suffix.Length)]);
    }

    private static void HandleConfirm(PluginConnection conn, IPluginCallbacks callbacks, string[] args, byte[] body)
    {
        var message = Encoding.UTF8.GetString(body);
        var yes = args.Length > 0 ? DecodeOptionLabel(args[0]) : "yes";
        var no = args.Length > 1 ? DecodeOptionLabel(args[1]) : null;

        conn.WriteStanza("ok", [callbacks.Confirm(message, yes, no) ? "yes" : "no"], []);
    }

    private static string DecodeOptionLabel(string arg)
    {
        try
        {
            return Encoding.UTF8.GetString(Base64Unpadded.Decode(arg));
        }
        catch (AgeFormatException)
        {
            throw new AgePluginException($"confirm option label is not valid unpadded base64: {arg}");
        }
    }
}
