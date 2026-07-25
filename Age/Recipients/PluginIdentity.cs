using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     An identity handled by an external <c>age-plugin-*</c> binary. Unwrapping
///     spawns the plugin named in the identity's HRP (e.g. <c>AGE-PLUGIN-YUBIKEY-1…</c>
///     runs <c>age-plugin-yubikey</c>) and drives the identity-v1 protocol.
/// </summary>
public sealed class PluginIdentity(string identity, IPluginCallbacks? callbacks = null) : IIdentityWithRecipient
{
    internal string PluginName { get; } =
        ExtractPluginName(identity);

    /// <summary>
    ///     A recipient that wraps to this identity, for encrypting to a key you hold — what
    ///     <c>age -e -i</c> does. The plugin does the wrapping via <c>add-identity</c>; no
    ///     public half is derived here, because only the plugin has one.
    /// </summary>
    public IRecipient Recipient =>
        PluginRecipient.ForIdentity(identity, PluginName, callbacks);

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
            var (type, args, body) = PluginProtocol.ReadStanza(conn);

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
                    PluginProtocol.HandleCommonStanza(conn, callbacks, type, args, body);
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

    internal static string ExtractPluginName(string identity) =>
        PluginProtocol.ExtractPluginName(identity, "age-plugin-", "-", "identity");

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