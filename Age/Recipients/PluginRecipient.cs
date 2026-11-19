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
    : IRecipient
{
    internal string PluginName { get; } =
        ExtractPluginName(recipient);

    /// <summary>
    /// Wraps the file key by running the plugin binary (recipient-v1 protocol). A plugin may
    /// answer with several stanzas; every one is returned.
    /// </summary>
    /// <exception cref="AgePluginException">The plugin failed.</exception>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "recipient-v1");
        return WrapAllWithConnection(conn, fileKey);
    }

    internal IReadOnlyList<Stanza> WrapAllWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        SendWrapRequest(conn, fileKey);
        return ReadWrapResponse(conn);
    }

    private void SendWrapRequest(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        conn.WriteStanza("add-recipient", [recipient], []);

        // Named, not inlined: an argument-position ToArray() leaves no reference to clear it by.
        var fileKeyCopy = fileKey.ToArray();

        try
        {
            conn.WriteStanza("wrap-file-key", [], fileKeyCopy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKeyCopy);
        }

        // No "extension-labels": advertising it promises we act on the plugin's "labels" reply,
        // and this recipient does not pass labels on yet (IRecipientWithLabels could). Staying
        // silent stops a conforming plugin from sending them, rather than having us discard a
        // constraint it relies on.
        conn.WriteStanza("done", [], []);
    }

    private List<Stanza> ReadWrapResponse(PluginConnection conn)
    {
        // Accumulate rather than replace: the spec's recipient-v1 example has one plugin emit two
        // stanzas for a single file index, and a share-splitting plugin needs all of them.
        var result = new List<Stanza>();

        while (true)
        {
            var (type, args, body) = conn.ReadNextStanza();

            switch (type)
            {
                case "recipient-stanza":
                    result.Add(ParseRecipientStanza(args, body));
                    conn.WriteStanza("ok", [], []);
                    break;

                case "error":
                    // Acknowledged first, as the spec requires and go-age does, then fatal.
                    conn.WriteStanza("ok", [], []);
                    throw conn.Failure($"plugin error: {Encoding.UTF8.GetString(body)}");

                case "done":
                    return result.Count > 0
                        ? result
                        : throw new AgePluginException("plugin completed without producing a recipient stanza");

                default:
                    PluginPrompts.Answer(conn, callbacks, type, args, body);
                    break;
            }
        }
    }

    private static Stanza ParseRecipientStanza(string[] args, byte[] body)
    {
        if (args.Length < 2)
            throw new AgePluginException("recipient-stanza missing file index or type");

        // One file key was sent, so 0 is the only index the plugin may answer with.
        if (args[0] != "0")
            throw new AgePluginException($"recipient-stanza has unexpected file index: {args[0]}");

        var stanzaType = args[1];
        var stanzaArgs = args.Length > 2 ? args[2..] : [];
        return new Stanza(stanzaType, stanzaArgs, body);
    }

    internal static string ExtractPluginName(string recipient)
    {
        // A plugin recipient HRP is "age1<name>" — "age1yubikey1..." gives name "yubikey". The prefix
        // check keeps hrp[4..] in range for a short HRP like "age".
        var (hrp, _) = Bech32.Decode(recipient);

        var name = hrp.StartsWith("age1", StringComparison.Ordinal)
            ? hrp[4..]
            : throw new FormatException($"invalid plugin recipient HRP: {hrp}");

        // The name becomes an executable path, so reject path separators before Process.Start.
        return PluginNameValidator.Validate(name);
    }

    /// <summary>Returns the plugin recipient string (public data).</summary>
    public override string ToString() =>
        recipient;
}