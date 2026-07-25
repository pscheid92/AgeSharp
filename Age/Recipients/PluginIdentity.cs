using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     An identity handled by an external <c>age-plugin-*</c> binary. Unwrapping
///     spawns the plugin named in the identity's HRP (e.g. <c>AGE-PLUGIN-YUBIKEY-1…</c>
///     runs <c>age-plugin-yubikey</c>) and drives the identity-v1 protocol.
/// </summary>
public sealed class PluginIdentity(string identity, IPluginCallbacks? callbacks = null) : IIdentity
{
    internal string PluginName { get; } =
        ExtractPluginName(identity);

    /// <summary>Attempts to unwrap a single stanza by running the plugin binary.</summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an internal error.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        return Unwrap([stanza]);
    }

    /// <summary>
    ///     Attempts to unwrap any of the stanzas in a single plugin session — one
    ///     process launch for the whole header, as the plugin protocol intends.
    /// </summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an internal error.</exception>
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

    internal static string ExtractPluginName(string identity)
    {
        var (hrp, _) = Bech32.Decode(identity);

        var name = hrp.StartsWith("age-plugin-") && hrp.EndsWith("-") && hrp.Length > 11
            ? hrp[11..^1]
            : throw new AgeFormatException($"invalid plugin identity HRP: {hrp}");

        // The name reaches Process.Start as age-plugin-<name>.
        return PluginNameValidator.Validate(name);
    }

    /// <summary>
    ///     Returns the raw <c>AGE-PLUGIN-…</c> identity string, e.g. for writing to an
    ///     identity file. Treat it as a secret: depending on the plugin it may encode
    ///     key material rather than just a hardware handle.
    /// </summary>
    public string ToSecretString()
    {
        return identity;
    }

    /// <summary>Redacted: shows only the public half, so logging cannot leak the secret. Never throws.</summary>
    public override string ToString()
    {
        return $"PluginIdentity({PluginName})";
    }
}