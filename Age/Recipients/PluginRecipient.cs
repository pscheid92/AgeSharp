using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     A recipient handled by an external <c>age-plugin-*</c> binary. Wrapping spawns
///     the plugin found on <c>PATH</c> for the recipient's HRP (e.g. <c>age1yubikey1…</c>
///     runs <c>age-plugin-yubikey</c>) and drives the recipient-v1 protocol.
/// </summary>
public sealed class PluginRecipient : IRecipient
{
    private readonly IPluginCallbacks? _callbacks;

    // recipient-v1 phase 1 takes either an add-recipient or an add-identity: a plugin
    // identity can wrap to itself, which is what `age -e -i` does (age-plugin.md).
    private readonly bool _isIdentity;
    private readonly string _encoding;

    /// <summary>Creates a recipient for a plugin recipient string (<c>age1&lt;name&gt;1…</c>).</summary>
    public PluginRecipient(string recipient, IPluginCallbacks? callbacks = null)
    {
        _encoding = recipient;
        _callbacks = callbacks;
        _isIdentity = false;
        PluginName = ExtractPluginName(recipient);
    }

    private PluginRecipient(string identity, string pluginName, IPluginCallbacks? callbacks)
    {
        _encoding = identity;
        _callbacks = callbacks;
        _isIdentity = true;
        PluginName = pluginName;
    }

    internal string PluginName { get; }

    // The plugin, not this library, holds whatever public half exists — so wrapping defers
    // back to it with add-identity rather than deriving anything here.
    internal static PluginRecipient ForIdentity(string identity, string pluginName, IPluginCallbacks? callbacks) =>
        new(identity, pluginName, callbacks);

    // Plugin-declared labels are not supported yet, so "extension-labels" is deliberately not
    // advertised: the spec requires a client offering it to enforce the labels it gets back.

    /// <summary>Wraps the file key by running the plugin binary (recipient-v1 protocol).</summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an error.</exception>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "recipient-v1");
        return WrapWithConnection(conn, fileKey);
    }

    internal IReadOnlyList<Stanza> WrapWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        SendWrapRequest(conn, fileKey);
        return ReadWrapResponse(conn);
    }

    private void SendWrapRequest(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        conn.WriteStanza(_isIdentity ? "add-identity" : "add-recipient", [_encoding], []);
        conn.WriteStanza("wrap-file-key", [], fileKey.ToArray());
        conn.WriteStanza("done", [], []);
    }

    private List<Stanza> ReadWrapResponse(PluginConnection conn)
    {
        // Accumulated, not replaced: one wrap-file-key may answer with several
        // recipient-stanzas for the same file index (age-plugin.md), which is how a plugin
        // stands for a group or several hardware slots. Keeping only the last would leave
        // the other recipients silently unable to decrypt.
        var stanzas = new List<Stanza>();

        while (true)
        {
            var (type, args, body) = PluginProtocol.ReadStanza(conn);

            switch (type)
            {
                case "recipient-stanza":
                    stanzas.Add(ParseRecipientStanza(args, body));
                    conn.WriteStanza("ok", [], []);
                    break;

                case "error":
                    throw new AgePluginException($"plugin error: {Encoding.UTF8.GetString(body)}");

                case "done":
                    return stanzas.Count > 0
                        ? stanzas
                        : throw new AgePluginException("plugin completed without producing a recipient stanza");

                default:
                    PluginProtocol.HandleCommonStanza(conn, _callbacks, type, args, body);
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

    internal static string ExtractPluginName(string recipient) =>
        PluginProtocol.ExtractPluginName(recipient, "age1", "", "recipient");

    /// <summary>Returns the plugin recipient string (public data).</summary>
    public override string ToString()
    {
        return _encoding;
    }
}