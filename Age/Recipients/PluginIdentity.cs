using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Plugin;

namespace Age.Recipients;

public sealed class PluginIdentity(string identity, IPluginCallbacks? callbacks = null) : IIdentity
{
    internal string PluginName { get; } =
        ExtractPluginName(identity);

    public byte[]? Unwrap(Stanza stanza) =>
        Unwrap([stanza]);

    public byte[]? Unwrap(IReadOnlyList<Stanza> stanzas)
    {
        using var conn = new PluginConnection(PluginName, "identity-v1");
        return UnwrapWithConnection(conn, stanzas);
    }

    internal byte[]? UnwrapWithConnection(PluginConnection conn, IReadOnlyList<Stanza> stanzas)
    {
        SendUnwrapRequest(conn, stanzas);
        return ReadUnwrapResponse(conn);
    }

    private void SendUnwrapRequest(PluginConnection conn, IReadOnlyList<Stanza> stanzas)
    {
        conn.WriteStanza("add-identity", [identity], []);

        for (var i = 0; i < stanzas.Count; i++)
        {
            var s = stanzas[i];
            string[] args = [i.ToString(), s.Type, .. s.Args];
            conn.WriteStanza("recipient-stanza", args, s.Body.ToArray());
        }

        conn.WriteStanza("done", [], []);
    }

    private byte[]? ReadUnwrapResponse(PluginConnection conn)
    {
        byte[]? result = null;

        while (true)
        {
            var (type, args, body) = ReadNextStanza(conn);

            switch (type)
            {
                case "file-key":
                    if (args.Length < 1)
                        throw new AgePluginException("file-key stanza missing file index");
                    result = body;
                    conn.WriteStanza("ok", [], []);
                    break;

                case "error":
                    HandleError(conn, args, body);
                    break;

                case "done":
                    return result;

                default:
                    HandleCommonStanza(conn, type, args, body);
                    break;
            }
        }
    }

    private static void HandleError(PluginConnection conn, string[] args, byte[] body)
    {
        if (args.Length > 0 && args[0] == "internal")
            throw new AgePluginException($"plugin internal error: {Encoding.UTF8.GetString(body)}");

        // Identity errors mean this identity doesn't match — return null
        conn.WriteStanza("ok", [], []);
    }

    private static (string Type, string[] Args, byte[] Body) ReadNextStanza(PluginConnection conn)
    {
        var raw = conn.ReadStanza() ?? throw new AgePluginException("unexpected end of plugin output");
        return raw;
    }

    private void HandleCommonStanza(PluginConnection conn, string type, string[] args, byte[] body)
    {
        switch (type)
        {
            // Per the age-plugin spec, interactive requests are answered with
            // fail when the client has no UI to present them
            case "msg" or "request-secret" or "confirm" when callbacks is null:
                conn.WriteStanza("fail", [], []);
                break;

            case "msg":
                callbacks!.DisplayMessage(Encoding.UTF8.GetString(body));
                conn.WriteStanza("ok", [], []);
                break;

            case "request-secret":
                var secret = callbacks!.RequestValue(Encoding.UTF8.GetString(body), true);
                conn.WriteStanza("ok", [], Encoding.UTF8.GetBytes(secret));
                break;

            case "confirm":
                HandleConfirm(conn, args, body);
                break;

            default:
                conn.WriteStanza("unsupported", [], []);
                break;
        }
    }

    private void HandleConfirm(PluginConnection conn, string[] args, byte[] body)
    {
        var message = Encoding.UTF8.GetString(body);
        var yes = args.Length > 0 ? DecodeOptionLabel(args[0]) : "yes";
        var no = args.Length > 1 ? DecodeOptionLabel(args[1]) : null;
        var confirmed = callbacks!.Confirm(message, yes, no);
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

    internal static string ExtractPluginName(string identity)
    {
        // Bech32-decode to get HRP. For "AGE-PLUGIN-YUBIKEY-1...", HRP = "age-plugin-yubikey-", name = HRP[11..^1] = "yubikey"
        var (hrp, _) = Bech32.Decode(identity);

        // A plugin identity HRP is "age-plugin-<name>-"; require both affixes (with room
        // between them) so the hrp[11..^1] slice can't run out of range on a malformed value.
        var name = hrp.StartsWith("age-plugin-") && hrp.EndsWith("-") && hrp.Length > 11
            ? hrp[11..^1]
            : throw new FormatException($"invalid plugin identity HRP: {hrp}");

        // The name becomes the age-plugin-<name> executable path, so reject anything
        // outside the allowed set (notably path separators) before it reaches Process.Start.
        return PluginNameValidator.Validate(name);
    }

    public override string ToString() =>
        identity;
}