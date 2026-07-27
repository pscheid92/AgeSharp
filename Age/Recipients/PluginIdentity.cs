using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Plugin;

namespace Age.Recipients;

/// <summary>
/// An identity handled by an external <c>age-plugin-*</c> binary. Unwrapping
/// spawns the plugin named in the identity's HRP (e.g. <c>AGE-PLUGIN-YUBIKEY-1…</c>
/// runs <c>age-plugin-yubikey</c>) and drives the identity-v1 protocol.
/// </summary>
/// <param name="identity">The plugin identity string (<c>AGE-PLUGIN-&lt;NAME&gt;-1…</c>).</param>
/// <param name="callbacks">
/// Optional UI callbacks for interactive plugins (PIN prompts, touch
/// confirmation); when null, interactive requests are answered with failure.
/// </param>
public sealed class PluginIdentity(string identity, IPluginCallbacks? callbacks = null) : IIdentity
{
    internal string PluginName { get; } =
        ExtractPluginName(identity);

    /// <summary>Attempts to unwrap a single stanza by running the plugin binary.</summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an internal error.</exception>
    public byte[]? Unwrap(Stanza stanza) =>
        Unwrap([stanza]);

    /// <summary>
    /// Attempts to unwrap any of the stanzas in a single plugin session — one
    /// process launch for the whole header, as the plugin protocol intends.
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

        // FILE_INDEX identifies the file, not the stanza: "Duplicate file indices indicate
        // stanzas that are from the same file header, and wrap the same file key." We are
        // decrypting exactly one file, so every stanza carries 0 — as go-age does. Numbering
        // them 0..n-1 presented one header as n phantom files, which defeats the spec's
        // same-index invalidation rule and stops a plugin from ever reassembling a file key
        // that is split across stanzas.
        foreach (var s in stanzas)
        {
            string[] args = ["0", s.Type, .. s.Args];
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
                    // One file was sent, so index 0 is the only valid answer, and a second
                    // file-key is a protocol error rather than a replacement — silently
                    // overwriting left the discarded key material unzeroed on the heap.
                    if (args.Length != 1 || args[0] != "0")
                        throw new AgePluginException(
                            $"file-key stanza has unexpected file index: {string.Join(' ', args)}");

                    if (result is not null)
                        throw new AgePluginException("duplicate file-key stanza");

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
        // See PluginRecipient.HandleConfirm — the yes label is mandatory per the spec, and
        // this pair of methods is duplicated verbatim across the two plugin types.
        if (args.Length is not (1 or 2))
            throw new AgePluginException("malformed confirm stanza: unexpected number of arguments");

        var message = Encoding.UTF8.GetString(body);
        var yes = DecodeOptionLabel(args[0]);
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
        var name = hrp.StartsWith("age-plugin-", StringComparison.Ordinal) && hrp.EndsWith("-", StringComparison.Ordinal) && hrp.Length > 11
            ? hrp[11..^1]
            : throw new FormatException($"invalid plugin identity HRP: {hrp}");

        // The name becomes the age-plugin-<name> executable path, so reject anything
        // outside the allowed set (notably path separators) before it reaches Process.Start.
        return PluginNameValidator.Validate(name);
    }

    /// <summary>
    /// Returns the raw <c>AGE-PLUGIN-…</c> identity string, e.g. for writing to an
    /// identity file. Treat it as a secret: depending on the plugin it may encode
    /// key material rather than just a hardware handle.
    /// </summary>
    public string ToSecretString() =>
        identity;

    /// <summary>
    /// Returns a redacted representation naming only the plugin, so accidental
    /// logging cannot leak the identity string. Use <see cref="ToSecretString"/>
    /// to export it.
    /// </summary>
    public override string ToString() =>
        $"PluginIdentity({PluginName})";
}