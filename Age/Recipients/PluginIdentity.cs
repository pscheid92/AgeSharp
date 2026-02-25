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
            var args = new string[s.Args.Length + 2];
            args[0] = i.ToString();
            args[1] = s.Type;
            Array.Copy(s.Args, 0, args, 2, s.Args.Length);
            conn.WriteStanza("recipient-stanza", args, s.Body);
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
            case "msg":
                callbacks?.DisplayMessage(Encoding.UTF8.GetString(body));
                conn.WriteStanza("ok", [], []);
                break;

            case "request-secret":
                if (callbacks is null)
                    throw new AgePluginException("plugin requested secret but no callbacks provided");
                var secret = callbacks.RequestValue(Encoding.UTF8.GetString(body), true);
                conn.WriteStanza("ok", [], Encoding.UTF8.GetBytes(secret));
                break;

            case "confirm":
                if (callbacks is null)
                    throw new AgePluginException("plugin requested confirmation but no callbacks provided");
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
        var yes = args.Length > 0 ? args[0] : "yes";
        var no = args.Length > 1 ? args[1] : null;
        var confirmed = callbacks!.Confirm(message, yes, no);
        conn.WriteStanza(confirmed ? "ok" : "fail", [], []);
    }

    internal static string ExtractPluginName(string identity)
    {
        // Bech32-decode to get HRP. For "AGE-PLUGIN-YUBIKEY-1...", HRP = "age-plugin-yubikey-", name = HRP[11..^1] = "yubikey"
        var (hrp, _) = Bech32.Decode(identity);

        // skip "age-plugin-" prefix and trailing "-"
        return hrp.StartsWith("age-plugin-")
            ? hrp[11..^1]
            : throw new FormatException($"invalid plugin identity HRP: {hrp}");
    }

    public override string ToString() =>
        identity;
}