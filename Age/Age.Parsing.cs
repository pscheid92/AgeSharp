using System.Diagnostics.CodeAnalysis;
using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

public static partial class Age
{
    /// <summary>
    ///     Parses a single recipient string: X25519 (<c>age1…</c>), ML-KEM-768-X25519
    ///     (<c>age1pq1…</c>), a plugin recipient (<c>age1&lt;name&gt;1…</c>), or an SSH
    ///     public key (an <c>ssh-ed25519</c> / <c>ssh-rsa</c> authorized_keys line).
    /// </summary>
    /// <exception cref="AgeFormatException">The string is not a recognized recipient.</exception>
    public static IRecipient ParseRecipient(string s, IPluginCallbacks? plugins = null)
    {
        // Dispatch on the true bech32 HRP — everything before the LAST '1' (BIP-173),
        // since data never contains '1'. String prefixes are ambiguous: 'p' and 'q'
        // are data characters, so an X25519 recipient can itself start with "age1pq".
        var sep = s.LastIndexOf('1');
        var hrp = sep > 0 ? s[..sep] : "";

        return hrp switch
        {
            "age" => X25519Recipient.Parse(s),
            "age1pq" => MlKem768X25519Recipient.Parse(s),
            _ when hrp.StartsWith("age1") => new PluginRecipient(s, plugins),
            _ when s.StartsWith("ssh-") => ParseSshRecipient(s),
            _ => throw new AgeFormatException($"unrecognized recipient: {s}")
        };
    }

    /// <summary>
    ///     Parses a single identity string: X25519 (<c>AGE-SECRET-KEY-1…</c>),
    ///     ML-KEM-768-X25519 (<c>AGE-SECRET-KEY-PQ-1…</c>), a plugin identity
    ///     (<c>AGE-PLUGIN-…</c>), or an SSH private key in PEM form.
    /// </summary>
    /// <exception cref="AgeFormatException">The string is not a recognized identity.</exception>
    public static IIdentity ParseIdentity(string s, IPluginCallbacks? plugins = null)
    {
        if (s.StartsWith("AGE-SECRET-KEY-PQ-", StringComparison.OrdinalIgnoreCase))
            return MlKem768X25519Identity.Parse(s);
        if (s.StartsWith("AGE-SECRET-KEY-", StringComparison.OrdinalIgnoreCase))
            return X25519Identity.Parse(s);
        if (s.StartsWith("AGE-PLUGIN-", StringComparison.OrdinalIgnoreCase))
            return new PluginIdentity(s, plugins);
        if (s.Contains("PRIVATE KEY"))
            return ParseSshIdentity(s);

        throw new AgeFormatException($"unrecognized identity: {s}");
    }

    /// <summary>Tries to parse a recipient string. Returns false instead of throwing.</summary>
    public static bool TryParseRecipient([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out IRecipient result) => 
        ParseHelpers.TryParse(s, static x => ParseRecipient(x), out result);

    /// <summary>Tries to parse an identity string. Returns false instead of throwing.</summary>
    public static bool TryParseIdentity([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out IIdentity result) => 
        ParseHelpers.TryParse(s, static x => ParseIdentity(x), out result);

    /// <summary>
    ///     Parses a recipients file: one recipient per line, with blank lines and
    ///     <c>#</c> comments ignored. The returned array is an
    ///     <see cref="IReadOnlyList{T}" />, so it can be passed straight to
    ///     <see cref="Encrypt(Stream, Stream, IReadOnlyList{IRecipient}, AgeEncryptOptions)" />
    ///     without wrapping.
    /// </summary>
    public static IRecipient[] ParseRecipients(string text, IPluginCallbacks? plugins = null) => 
        NonBlankLines(text).Select(line => ParseRecipient(line, plugins)).ToArray();

    /// <summary>
    ///     Parses a plaintext identity file: one identity per line, with blank lines
    ///     and <c>#</c> comments ignored.
    /// </summary>
    public static IIdentity[] ParseIdentities(string text, IPluginCallbacks? plugins = null) => 
        NonBlankLines(text).Select(line => ParseIdentity(line, plugins)).ToArray();

    /// <summary>
    ///     Decrypts a passphrase-protected identity file and parses the identities it
    ///     contains.
    /// </summary>
    public static IIdentity[] DecryptIdentities(Stream source, string passphrase, IPluginCallbacks? plugins = null)
    {
        using var output = new MemoryStream();
        Decrypt(source, output, [new Passphrase(passphrase)]);
        return ParseIdentities(Encoding.UTF8.GetString(output.ToArray()), plugins);
    }

    private static IEnumerable<string> NonBlankLines(string text) =>
        text.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Length > 0 && !line.StartsWith('#'));

    private static IRecipient ParseSshRecipient(string authorizedKeysLine)
    {
        var (keyType, _, _) = SshKeyParser.ParsePublicKey(authorizedKeysLine);
        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Recipient.Parse(authorizedKeysLine),
            "ssh-rsa" => SshRsaRecipient.Parse(authorizedKeysLine),
            _ => throw new AgeFormatException($"unsupported SSH key type: {keyType}")
        };
    }

    private static IIdentity ParseSshIdentity(string pemText)
    {
        var (keyType, _, _) = SshKeyParser.ParsePrivateKey(pemText);
        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Identity.Parse(pemText),
            "ssh-rsa" => SshRsaIdentity.Parse(pemText),
            _ => throw new AgeFormatException($"unsupported SSH key type: {keyType}")
        };
    }
}