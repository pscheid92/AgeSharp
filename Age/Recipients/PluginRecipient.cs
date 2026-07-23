using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Plugin;

namespace Age.Recipients;

/// <summary>
/// A recipient handled by an external <c>age-plugin-*</c> binary. Wrapping spawns
/// the plugin found on <c>PATH</c> for the recipient's HRP (e.g. <c>age1yubikey1…</c>
/// runs <c>age-plugin-yubikey</c>) and drives the recipient-v1 protocol.
/// </summary>
/// <param name="recipient">The plugin recipient string (<c>age1&lt;name&gt;1…</c>).</param>
/// <param name="callbacks">
/// Optional UI callbacks for interactive plugins; when null, interactive
/// requests are answered with failure per the plugin protocol.
/// </param>
public sealed class PluginRecipient(string recipient, IPluginCallbacks? callbacks = null) : IRecipient
{
    internal string PluginName { get; } =
        ExtractPluginName(recipient);

    /// <summary>Plugin recipients declare no security label.</summary>
    public string? Label =>
        null;


    /// <summary>Wraps the file key by running the plugin binary (recipient-v1 protocol).</summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an error.</exception>
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
            // Per the age-plugin spec, interactive requests are answered with
            // fail when the client has no UI to present them
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
        catch (AgeFormatException)
        {
            throw new AgePluginException($"confirm option label is not valid unpadded base64: {arg}");
        }
    }

    internal static string ExtractPluginName(string recipient)
    {
        // Bech32-decode to get HRP. For "age1yubikey1...", HRP = "age1yubikey", name = HRP[4..] = "yubikey"
        var (hrp, _) = Bech32.Decode(recipient);

        // A plugin recipient HRP is "age1<name>"; require the "age1" prefix so hrp[4..]
        // is always in range (a shorter HRP like "age" would otherwise throw).
        var name = hrp.StartsWith("age1")
            ? hrp[4..]
            : throw new AgeFormatException($"invalid plugin recipient HRP: {hrp}");

        // The name becomes the age-plugin-<name> executable path, so reject anything
        // outside the allowed set (notably path separators) before it reaches Process.Start.
        return PluginNameValidator.Validate(name);
    }

    /// <summary>Returns the plugin recipient string (public data).</summary>
    public override string ToString() =>
        recipient;
}