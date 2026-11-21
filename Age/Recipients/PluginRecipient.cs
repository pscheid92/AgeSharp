using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
namespace AgeSharp;

/// <summary>
/// A recipient handled by an external <c>age-plugin-*</c> binary. Wrapping spawns
/// the plugin found on <c>PATH</c> for the recipient's HRP (e.g. <c>age1yubikey1…</c>
/// runs <c>age-plugin-yubikey</c>) and drives the recipient-v1 protocol.
/// </summary>
/// <remarks>
/// <para>
/// A plugin identity's <see cref="PluginIdentity.Recipient"/> is one too: it hands the plugin the
/// identity instead (<c>add-identity</c>), for plugins that can encrypt to their identities.
/// </para>
/// <para>
/// The plugin may declare security labels for what it wraps, such as <c>postquantum</c>; they
/// are passed on, so a file never mixes recipients that declare different ones (see
/// <see cref="IRecipientWithLabels"/>). A plugin that declares none has none.
/// </para>
/// </remarks>
public sealed class PluginRecipient : IRecipientWithLabels
{
    // A recipient string, or for an identity's recipient the identity string, which is secret.
    private readonly string _encoding;
    private readonly bool _fromIdentity;
    private readonly IPluginCallbacks? _plugins;

    internal PluginRecipient(string recipient, IPluginCallbacks? plugins = null)
    {
        _encoding = recipient;
        _plugins = plugins;
        PluginName = ExtractPluginName(recipient);
    }

    private PluginRecipient(string identity, string pluginName, IPluginCallbacks? plugins)
    {
        _encoding = identity;
        _fromIdentity = true;
        _plugins = plugins;
        PluginName = pluginName;
    }

    // go-age's Identity.Recipient: the plugin is handed the identity, and wraps to it.
    internal static PluginRecipient ForIdentity(string identity, string pluginName, IPluginCallbacks? plugins) =>
        new(identity, pluginName, plugins);

    /// <summary>Parses a plugin recipient, <c>age1&lt;name&gt;1…</c>.</summary>
    /// <param name="s">The recipient string.</param>
    /// <param name="plugins">
    /// Lets the plugin talk to the user; without it, its requests are answered as failures, as
    /// the plugin protocol specifies.
    /// </param>
    /// <exception cref="FormatException">The string is not a plugin recipient, or names no valid plugin.</exception>
    public static PluginRecipient Parse(string s, IPluginCallbacks? plugins = null)
    {
        ArgumentNullException.ThrowIfNull(s);
        return new PluginRecipient(s, plugins);
    }

    internal string PluginName { get; }

    /// <summary>
    /// Wraps the file key by running the plugin binary (recipient-v1 protocol). A plugin may
    /// answer with several stanzas; every one is returned.
    /// </summary>
    /// <exception cref="AgePluginException">The plugin failed.</exception>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) =>
        WrapWithLabels(fileKey).Stanzas;

    /// <summary>Wraps the file key, with the labels the plugin declares for its stanzas.</summary>
    /// <exception cref="AgePluginException">The plugin failed, or declared its labels twice.</exception>
    public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "recipient-v1");
        return WrapWithConnection(conn, fileKey);
    }

    internal LabelledStanzas WrapWithConnection(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        SendWrapRequest(conn, fileKey);
        return ReadWrapResponse(conn);
    }

    private void SendWrapRequest(PluginConnection conn, ReadOnlySpan<byte> fileKey)
    {
        conn.WriteStanza(_fromIdentity ? "add-identity" : "add-recipient", [_encoding], []);

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

        // Promises to act on the plugin's labels, which WrapWithLabels does.
        conn.WriteStanza("extension-labels", [], []);
        conn.WriteStanza("done", [], []);
    }

    private LabelledStanzas ReadWrapResponse(PluginConnection conn)
    {
        // Accumulate rather than replace: the spec's recipient-v1 example has one plugin emit two
        // stanzas for a single file index, and a share-splitting plugin needs all of them.
        var result = new List<Stanza>();

        // No labels reply means the empty set (age-plugin.md: "MUST treat ... as having an empty
        // label set").
        string[]? labels = null;

        while (true)
        {
            var (type, args, body) = PluginPrompts.Read(conn, _plugins, PluginName);

            switch (type)
            {
                case "recipient-stanza":
                    result.Add(ParseRecipientStanza(args, body));
                    conn.WriteStanza("ok", [], []);
                    break;

                case "labels":
                    labels = labels is null ? args : throw new AgePluginException("plugin declared its labels twice");
                    conn.WriteStanza("ok", [], []);
                    break;

                case "error":
                    // Acknowledged first, as the spec requires and go-age does, then fatal.
                    conn.WriteStanza("ok", [], []);
                    throw conn.Failure($"plugin error: {Encoding.UTF8.GetString(body)}");

                case "done":
                    return result.Count > 0
                        ? new LabelledStanzas(result, labels ?? [])
                        : throw new AgePluginException("plugin completed without producing a recipient stanza");

                default:
                    PluginPrompts.Answer(conn, _plugins, PluginName, type, args, body);
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

    /// <summary>
    /// Returns the plugin recipient string (public data). A plugin identity's recipient has none,
    /// and its identity string may be a secret, so it renders as
    /// <c>PluginRecipient(&lt;plugin&gt;, from identity)</c>.
    /// </summary>
    public override string ToString() =>
        _fromIdentity ? $"PluginRecipient({PluginName}, from identity)" : _encoding;
}