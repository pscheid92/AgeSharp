using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Plugin;

namespace Age.Recipients;

public sealed class PluginRecipient : IRecipient
{
    private readonly string _recipient;
    private readonly string _pluginName;
    private readonly IPluginCallbacks? _callbacks;

    public PluginRecipient(string recipient, IPluginCallbacks? callbacks = null)
    {
        _recipient = recipient;
        _pluginName = ExtractPluginName(recipient);
        _callbacks = callbacks;
    }

    public string? Label => null;

    internal string PluginName => _pluginName;

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(_pluginName, "recipient-v1");
        return WrapWithConnection(conn, fileKey);
    }

    internal Stanza WrapWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        // Phase 1: send stanzas to plugin
        conn.WriteStanza("add-recipient", [_recipient], []);
        conn.WriteStanza("wrap-file-key", [], fileKey.ToArray());
        conn.WriteStanza("extension-labels", [], []);
        conn.WriteStanza("done", [], []);

        // Phase 2: read response stanzas
        Stanza? result = null;
        while (true)
        {
            var raw = conn.ReadStanza();
            if (raw is null)
                throw new AgePluginException("unexpected end of plugin output");
            var (type, args, body) = raw.Value;

            switch (type)
            {
                case "recipient-stanza":
                    if (args.Length < 2)
                        throw new AgePluginException("recipient-stanza missing file index or type");
                    var stanzaType = args[1];
                    var stanzaArgs = args.Length > 2 ? args[2..] : [];
                    result = new Stanza(stanzaType, stanzaArgs, body);
                    conn.WriteStanza("ok", [], []);
                    break;

                case "msg":
                    var message = Encoding.UTF8.GetString(body);
                    if (_callbacks is not null)
                        _callbacks.DisplayMessage(message);
                    conn.WriteStanza("ok", [], []);
                    break;

                case "request-secret":
                    if (_callbacks is null)
                        throw new AgePluginException("plugin requested secret but no callbacks provided");
                    var prompt = Encoding.UTF8.GetString(body);
                    var secret = _callbacks.RequestValue(prompt, true);
                    conn.WriteStanza("ok", [], Encoding.UTF8.GetBytes(secret));
                    break;

                case "confirm":
                    if (_callbacks is null)
                        throw new AgePluginException("plugin requested confirmation but no callbacks provided");
                    HandleConfirm(conn, args, body);
                    break;

                case "error":
                    var errorMsg = Encoding.UTF8.GetString(body);
                    throw new AgePluginException($"plugin error: {errorMsg}");

                case "done":
                    if (result is null)
                        throw new AgePluginException("plugin completed without producing a recipient stanza");
                    return result;

                default:
                    // Unknown stanza — respond with unsupported
                    conn.WriteStanza("unsupported", [], []);
                    break;
            }
        }
    }

    private void HandleConfirm(PluginConnection conn, string[] args, byte[] body)
    {
        var message = Encoding.UTF8.GetString(body);
        var yes = args.Length > 0 ? args[0] : "yes";
        var no = args.Length > 1 ? args[1] : null;
        var confirmed = _callbacks!.Confirm(message, yes, no);
        if (confirmed)
            conn.WriteStanza("ok", [], []);
        else
            conn.WriteStanza("fail", [], []);
    }

    internal static string ExtractPluginName(string recipient)
    {
        // Bech32-decode to get HRP. For "age1yubikey1...", HRP = "age1yubikey", name = HRP[4..] = "yubikey"
        var (hrp, _) = Bech32.Decode(recipient);
        if (!hrp.StartsWith("age"))
            throw new FormatException($"invalid plugin recipient HRP: {hrp}");
        return hrp[4..]; // skip "age" + the "1" separator character encoded in hrp after "age"
    }

    public override string ToString() => _recipient;
}
