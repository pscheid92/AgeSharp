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

    /// <summary>Tries to unwrap a single stanza by running the plugin binary.</summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an internal error.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) =>
        TryUnwrap([stanza], fileKey);

    /// <summary>
    /// Tries to unwrap any of the stanzas in a single plugin session — one
    /// process launch for the whole header, as the plugin protocol intends.
    /// </summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an internal error.</exception>
    public bool TryUnwrap(IReadOnlyList<Stanza> stanzas, Span<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "identity-v1");
        return FileKey.Deliver(UnwrapWithConnection(conn, stanzas), fileKey);
    }

    internal byte[]? UnwrapWithConnection(PluginConnection conn, IReadOnlyList<Stanza> stanzas)
    {
        SendUnwrapRequest(conn, stanzas);
        return ReadUnwrapResponse(conn);
    }

    private void SendUnwrapRequest(PluginConnection conn, IReadOnlyList<Stanza> stanzas)
    {
        conn.WriteStanza("add-identity", [identity], []);

        // FILE_INDEX identifies the file, not the stanza: "Duplicate file indices indicate stanzas
        // that are from the same file header, and wrap the same file key." One file, so all carry 0.
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
            var (type, args, body) = conn.ReadNextStanza();

            switch (type)
            {
                case "file-key":
                    // One file was sent, so 0 is the only valid index, and a second file-key is a protocol
                    // error rather than a replacement.
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
                    PluginPrompts.Answer(conn, callbacks, type, args, body);
                    break;
            }
        }
    }

    /// <summary>
    /// Acknowledges the error as the spec requires, then fails with the plugin's message.
    /// </summary>
    /// <remarks>
    /// Every kind is fatal, as in go-age (plugin/client.go). An identity error is how a plugin
    /// says "wrong PIN" or "no token inserted", and a stanza error means the header is invalid;
    /// neither means "not for this identity", which a plugin says by finishing without a file key.
    /// </remarks>
    private static void HandleError(PluginConnection conn, string[] args, byte[] body)
    {
        conn.WriteStanza("ok", [], []);

        var kind = args.Length > 0 ? $"{args[0]} " : "";
        throw conn.Failure($"plugin {kind}error: {Encoding.UTF8.GetString(body)}");
    }

    internal static string ExtractPluginName(string identity)
    {
        // A plugin identity HRP is "age-plugin-<name>-" — "AGE-PLUGIN-YUBIKEY-1..." gives "yubikey".
        // Both affixes are required so hrp[11..^1] cannot run out of range.
        var (hrp, _) = Bech32.Decode(identity);

        var name = hrp.StartsWith("age-plugin-", StringComparison.Ordinal) && hrp.EndsWith("-", StringComparison.Ordinal) && hrp.Length > 11
            ? hrp[11..^1]
            : throw new FormatException($"invalid plugin identity HRP: {hrp}");

        // The name becomes an executable path, so reject path separators before Process.Start.
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