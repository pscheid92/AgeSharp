using System.Security.Cryptography;
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
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        return TryUnwrap([stanza], fileKey);
    }

    /// <summary>
    ///     Attempts to unwrap any of the stanzas in a single plugin session — one
    ///     process launch for the whole header, as the plugin protocol intends.
    /// </summary>
    /// <exception cref="AgePluginException">The plugin failed, misbehaved, or reported an internal error.</exception>
    public bool TryUnwrap(IReadOnlyList<Stanza> stanzas, Span<byte> fileKey)
    {
        using var conn = new PluginConnection(PluginName, "identity-v1");
        return TryUnwrapWithConnection(conn, stanzas, fileKey);
    }

    // The plugin hands the file key back over the wire as an array, so this copies it into
    // the caller's buffer and clears the wire copy.
    internal bool TryUnwrapWithConnection(PluginConnection conn, IReadOnlyList<Stanza> stanzas, Span<byte> fileKey)
    {
        SendUnwrapRequest(conn, stanzas);
        var unwrapped = ReadUnwrapResponse(conn);

        if (unwrapped is null)
            return false;

        try
        {
            if (unwrapped.Length != fileKey.Length)
                throw new AgePluginException(
                    $"plugin returned a {unwrapped.Length}-byte file key, expected {fileKey.Length}");

            unwrapped.CopyTo(fileKey);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(unwrapped);
        }
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