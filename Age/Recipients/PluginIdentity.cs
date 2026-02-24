using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Plugin;

namespace Age.Recipients;

public sealed class PluginIdentity : IIdentity
{
    private readonly string _identity;
    private readonly string _pluginName;
    private readonly IPluginCallbacks? _callbacks;

    public PluginIdentity(string identity, IPluginCallbacks? callbacks = null)
    {
        _identity = identity;
        _pluginName = ExtractPluginName(identity);
        _callbacks = callbacks;
    }

    internal string PluginName => _pluginName;

    public byte[]? Unwrap(Stanza stanza) => Unwrap(new List<Stanza> { stanza });

    public byte[]? Unwrap(IReadOnlyList<Stanza> stanzas)
    {
        using var conn = new PluginConnection(_pluginName, "identity-v1");
        return UnwrapWithConnection(conn, stanzas);
    }

    internal byte[]? UnwrapWithConnection(PluginConnection conn, IReadOnlyList<Stanza> stanzas)
    {
        // Phase 1: send identity and all stanzas
        conn.WriteStanza("add-identity", [_identity], []);
        for (int i = 0; i < stanzas.Count; i++)
        {
            var s = stanzas[i];
            var args = new string[s.Args.Length + 2];
            args[0] = i.ToString();
            args[1] = s.Type;
            Array.Copy(s.Args, 0, args, 2, s.Args.Length);
            conn.WriteStanza("recipient-stanza", args, s.Body);
        }
        conn.WriteStanza("done", [], []);

        // Phase 2: read response stanzas
        byte[]? result = null;
        while (true)
        {
            var raw = conn.ReadStanza();
            if (raw is null)
                throw new AgePluginException("unexpected end of plugin output");
            var (type, args, body) = raw.Value;

            switch (type)
            {
                case "file-key":
                    if (args.Length < 1)
                        throw new AgePluginException("file-key stanza missing file index");
                    result = body;
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
                    if (args.Length > 0 && args[0] == "internal")
                    {
                        var errorMsg = Encoding.UTF8.GetString(body);
                        throw new AgePluginException($"plugin internal error: {errorMsg}");
                    }
                    // Identity errors mean this identity doesn't match — return null
                    conn.WriteStanza("ok", [], []);
                    break;

                case "done":
                    return result;

                default:
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

    internal static string ExtractPluginName(string identity)
    {
        // Bech32-decode to get HRP. For "AGE-PLUGIN-YUBIKEY-1...", HRP = "age-plugin-yubikey-", name = HRP[11..^1] = "yubikey"
        var (hrp, _) = Bech32.Decode(identity);
        if (!hrp.StartsWith("age-plugin-"))
            throw new FormatException($"invalid plugin identity HRP: {hrp}");
        return hrp[11..^1]; // skip "age-plugin-" prefix and trailing "-"
    }

    public override string ToString() => _identity;
}
