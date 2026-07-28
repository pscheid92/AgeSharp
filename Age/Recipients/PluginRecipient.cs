using System.Security.Cryptography;
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
public sealed class PluginRecipient(string recipient, IPluginCallbacks? callbacks = null)
    : IRecipient, IMultiStanzaRecipient
{
    internal string PluginName { get; } =
        ExtractPluginName(recipient);

    /// <summary>Plugin recipients declare no security label.</summary>
    public string? Label =>
        null;


    /// <summary>
    /// Wraps the file key by running the plugin binary (recipient-v1 protocol).
    /// </summary>
    /// <remarks>
    ///     A plugin is permitted to answer with several stanzas. This returns a single one and so
    ///     cannot represent that, and silently dropping the rest would destroy the file key beyond
    ///     recovery — so it throws instead. The library itself does not go through here: it uses
    ///     the multi-stanza path and keeps every stanza.
    /// </remarks>
    /// <exception cref="AgePluginException">The plugin failed, or produced more than one stanza.</exception>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "recipient-v1");
        var stanzas = WrapAllWithConnection(conn, fileKey);

        return stanzas.Count == 1
            ? stanzas[0]
            : throw new AgePluginException(
                $"plugin '{PluginName}' produced {stanzas.Count} recipient stanzas, which a single " +
                "Stanza cannot carry; encrypt through Age instead of calling Wrap directly");
    }

    IReadOnlyList<Stanza> IMultiStanzaRecipient.WrapAll(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "recipient-v1");
        return WrapAllWithConnection(conn, fileKey);
    }

    internal Stanza WrapWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        var stanzas = WrapAllWithConnection(conn, fileKey);

        return stanzas.Count == 1
            ? stanzas[0]
            : throw new AgePluginException(
                $"plugin '{PluginName}' produced {stanzas.Count} recipient stanzas");
    }

    internal IReadOnlyList<Stanza> WrapAllWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        SendWrapRequest(conn, fileKey);
        return ReadWrapResponse(conn);
    }

    private void SendWrapRequest(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        conn.WriteStanza("add-recipient", [recipient], []);

        // Named rather than inlined so the raw copy of the file key can be cleared; passing
        // fileKey.ToArray() as an argument left it on the heap with no reference to clear it by.
        var fileKeyCopy = fileKey.ToArray();

        try
        {
            conn.WriteStanza("wrap-file-key", [], fileKeyCopy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKeyCopy);
        }

        // Deliberately no "extension-labels": advertising it promises we will act
        // on the plugin's "labels" reply, and IRecipient.Label cannot carry a
        // label set. Staying silent keeps a conforming plugin from sending
        // "labels" at all, rather than having us discard a constraint it relies on.
        conn.WriteStanza("done", [], []);
    }

    private List<Stanza> ReadWrapResponse(PluginConnection conn)
    {
        // Accumulate: the spec's own recipient-v1 example has a plugin emit two stanzas for one
        // file index, and go-age appends. Overwriting here discarded every stanza but the last,
        // which for a share-splitting plugin means the file key can never be reassembled.
        var result = new List<Stanza>();

        while (true)
        {
            var (type, args, body) = ReadNextStanza(conn);

            switch (type)
            {
                case "recipient-stanza":
                    result.Add(ParseRecipientStanza(args, body));
                    conn.WriteStanza("ok", [], []);
                    break;

                case "error":
                    throw conn.Failure($"plugin error: {Encoding.UTF8.GetString(body)}");

                case "done":
                    return result.Count > 0
                        ? result
                        : throw new AgePluginException("plugin completed without producing a recipient stanza");

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

        // We send exactly one file key, so the only index the plugin may answer with is 0.
        // Accepting a stanza addressed to a file we never mentioned is protocol
        // non-conformance; go-age rejects it outright.
        if (args[0] != "0")
            throw new AgePluginException($"recipient-stanza has unexpected file index: {args[0]}");

        var stanzaType = args[1];
        var stanzaArgs = args.Length > 2 ? args[2..] : [];
        return new Stanza(stanzaType, stanzaArgs, body);
    }

    private static (string Type, string[] Args, byte[] Body) ReadNextStanza(PluginConnection conn)
    {
        // The plugin died or closed stdout. Its stderr is the only account of why, so it is
        // quoted into the message rather than discarded.
        var raw = conn.ReadStanza() ?? throw conn.Failure("unexpected end of plugin output");
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
        // (confirm, Base64(YES_STRING) [Base64(NO_STRING)]; MESSAGE) — the yes label is
        // mandatory, so a missing one is a malformed command, not a prompt to invent a label for.
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

    internal static string ExtractPluginName(string recipient)
    {
        // Bech32-decode to get HRP. For "age1yubikey1...", HRP = "age1yubikey", name = HRP[4..] = "yubikey"
        var (hrp, _) = Bech32.Decode(recipient);

        // A plugin recipient HRP is "age1<name>"; require the "age1" prefix so hrp[4..]
        // is always in range (a shorter HRP like "age" would otherwise throw).
        var name = hrp.StartsWith("age1", StringComparison.Ordinal)
            ? hrp[4..]
            : throw new FormatException($"invalid plugin recipient HRP: {hrp}");

        // The name becomes the age-plugin-<name> executable path, so reject anything
        // outside the allowed set (notably path separators) before it reaches Process.Start.
        return PluginNameValidator.Validate(name);
    }

    /// <summary>Returns the plugin recipient string (public data).</summary>
    public override string ToString() =>
        recipient;
}