using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Plugin;

namespace Age.Recipients;

public sealed class PluginRecipient(string recipient, IPluginCallbacks? callbacks = null) : IRecipient
{
    internal string PluginName { get; } =
        ExtractPluginName(recipient);

    public string? Label =>
        null;


    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "recipient-v1");
        return WrapWithConnection(conn, fileKey);
    }

    internal Stanza WrapWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        SendWrapRequest(conn, fileKey);
        return ReadWrapResponse(conn);
    }

    private void SendWrapRequest(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        conn.WriteStanza("add-recipient", [recipient], []);
        conn.WriteStanza("wrap-file-key", [], fileKey.ToArray());
        conn.WriteStanza("extension-labels", [], []);
        conn.WriteStanza("done", [], []);
    }

    private Stanza ReadWrapResponse(PluginConnection conn)
    {
        Stanza? result = null;

        while (true)
        {
            var (type, args, body) = ReadNextStanza(conn);

            switch (type)
            {
                case "recipient-stanza":
                    result = ParseRecipientStanza(args, body);
                    conn.WriteStanza("ok", [], []);
                    break;

                case "error":
                    throw new AgePluginException($"plugin error: {Encoding.UTF8.GetString(body)}");

                case "done":
                    return result
                           ?? throw new AgePluginException("plugin completed without producing a recipient stanza");

                default:
                    HandleCommonStanza(conn, type, args, body);
                    break;
            }
        }
    }

    private static Stanza ParseRecipientStanza(string[] args, byte[] body)
    {
        if (args.Length < 2)
            throw new AgePluginException("recipient-stanza missing file index or type");

        var stanzaType = args[1];
        var stanzaArgs = args.Length > 2 ? args[2..] : [];
        return new Stanza(stanzaType, stanzaArgs, body);
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

    internal static string ExtractPluginName(string recipient)
    {
        // Bech32-decode to get HRP. For "age1yubikey1...", HRP = "age1yubikey", name = HRP[4..] = "yubikey"
        var (hrp, _) = Bech32.Decode(recipient);

        // skip "age" + the "1" separator character encoded in hrp after "age"
        return hrp.StartsWith("age")
            ? hrp[4..]
            : throw new FormatException($"invalid plugin recipient HRP: {hrp}");
    }

    public override string ToString() =>
        recipient;
}