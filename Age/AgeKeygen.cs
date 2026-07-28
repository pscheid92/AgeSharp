using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Plugin;
using Age.Recipients;

namespace Age;

/// <summary>
/// Key generation and key/identity-file parsing: single keys, recipients files
/// (<c>-R</c> style), plaintext identity files (<c>-i</c> style), and
/// passphrase-protected identity files.
/// </summary>
public static class AgeKeygen
{
    /// <summary>Generates a new X25519 identity (the <c>age-keygen</c> default).</summary>
    public static X25519Identity Generate() =>
        X25519Identity.Generate();

    /// <summary>Parses an X25519 secret key (<c>AGE-SECRET-KEY-1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 secret key.</exception>
    public static X25519Identity ParseIdentity(string s) =>
        X25519Identity.Parse(s);

    /// <summary>Parses an X25519 recipient (<c>age1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 recipient.</exception>
    public static X25519Recipient ParseRecipient(string s) =>
        X25519Recipient.Parse(s);

    /// <summary>Generates a new post-quantum ML-KEM-768-X25519 identity.</summary>
    public static MlKem768X25519Identity GeneratePq() =>
        MlKem768X25519Identity.Generate();

    /// <summary>Parses an ML-KEM-768-X25519 secret key (<c>AGE-SECRET-KEY-PQ-1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid ML-KEM-768-X25519 secret key.</exception>
    public static MlKem768X25519Identity ParsePqIdentity(string s) =>
        MlKem768X25519Identity.Parse(s);

    /// <summary>Parses an ML-KEM-768-X25519 recipient (<c>age1pq1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid ML-KEM-768-X25519 recipient.</exception>
    public static MlKem768X25519Recipient ParsePqRecipient(string s) =>
        MlKem768X25519Recipient.Parse(s);

    /// <summary>
    /// Parses an SSH public key from an authorized_keys line and returns the appropriate recipient.
    /// Supports ssh-ed25519 and ssh-rsa key types.
    /// </summary>
    public static IRecipient ParseSshRecipient(string authorizedKeysLine)
    {
        var (keyType, _, _) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Recipient.Parse(authorizedKeysLine),
            "ssh-rsa" => SshRsaRecipient.Parse(authorizedKeysLine),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    /// <summary>
    /// Parses an SSH private key from PEM text and returns the appropriate identity.
    /// Supports ssh-ed25519 and ssh-rsa key types in OpenSSH, PKCS#1, or PKCS#8 format.
    /// </summary>
    public static IIdentity ParseSshIdentity(string pemText)
    {
        var (keyType, _, _) = SshKeyParser.ParsePrivateKey(pemText);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Identity.Parse(pemText),
            "ssh-rsa" => SshRsaIdentity.Parse(pemText),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    /// <summary>
    /// Parses a recipients file containing public keys, comments, and blank lines.
    /// Supports age X25519 (age1...), ML-KEM-768 (age1pq...), plugin (age1name1...), and SSH public keys.
    /// The returned array converts implicitly to the <c>ReadOnlySpan&lt;IRecipient&gt;</c>
    /// that <see cref="AgeEncrypt.Encrypt(Stream, Stream, ReadOnlySpan{IRecipient})"/> accepts.
    /// </summary>
    public static IRecipient[] ParseRecipientsFile(string text, IPluginCallbacks? callbacks = null) =>
        text.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(line => ParseRecipientLine(line, callbacks))
            .ToArray();

    /// <summary>
    /// Parses a single recipient string: age X25519, ML-KEM-768, plugin, or SSH public key.
    /// </summary>
    internal static IRecipient ParseRecipientLine(string line, IPluginCallbacks? callbacks)
    {
        // Dispatch on the true bech32 HRP — everything before the LAST '1' (BIP-173), since
        // data never contains '1'. String prefixes are ambiguous here: 'p' and 'q' are data
        // characters, so an X25519 recipient's data can itself start with "pq" ("age1pq...").
        var sep = line.LastIndexOf('1');
        var hrp = sep > 0 ? line[..sep] : "";

        return hrp switch
        {
            "age" => X25519Recipient.Parse(line),
            "age1pq" => MlKem768X25519Recipient.Parse(line),
            _ when hrp.StartsWith("age1", StringComparison.Ordinal) => new PluginRecipient(line, callbacks),
            _ when line.StartsWith("ssh-", StringComparison.Ordinal) => ParseSshRecipient(line),
            _ => throw new FormatException($"unrecognized recipient: {line}")
        };
    }

    /// <summary>
    /// Parses a plaintext identity file containing AGE-SECRET-KEY lines, plugin identities, comments, and blank lines.
    /// The returned array converts implicitly to the <c>ReadOnlySpan&lt;IIdentity&gt;</c>
    /// that <see cref="AgeEncrypt.Decrypt(Stream, Stream, ReadOnlySpan{IIdentity})"/> accepts.
    /// </summary>
    public static IIdentity[] ParseIdentityFile(string text, IPluginCallbacks? callbacks = null)
    {
        var identities = new List<IIdentity>();

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;

            if (trimmed.StartsWith("AGE-SECRET-KEY-PQ-", StringComparison.Ordinal))
                identities.Add(MlKem768X25519Identity.Parse(trimmed));
            else if (trimmed.StartsWith("AGE-SECRET-KEY-", StringComparison.Ordinal))
                identities.Add(X25519Identity.Parse(trimmed));
            else if (trimmed.StartsWith("AGE-PLUGIN-", StringComparison.Ordinal))
                identities.Add(new PluginIdentity(trimmed, callbacks));
            else
                throw new FormatException($"unrecognized line in identity file: {trimmed}");
        }

        return [.. identities];
    }

    /// <summary>
    /// Decrypts an encrypted (passphrase-protected) identity file and parses the contained identities.
    /// </summary>
    /// <remarks>
    ///     The decrypted file contains <c>AGE-SECRET-KEY-1…</c> lines in the clear. The byte
    ///     copies are cleared here; the <see cref="string" /> they are decoded into cannot be,
    ///     because <see cref="ParseIdentityFile" /> takes a string and is shipped public API.
    ///     Treat this as reducing the exposure rather than eliminating it.
    /// </remarks>
    public static IIdentity[] DecryptIdentityFile(byte[] data, string passphrase)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();

        AgeEncrypt.Decrypt(input, output, new ScryptRecipient(passphrase));

        // ToArray copies out, and the MemoryStream's own buffer keeps the plaintext too —
        // Dispose does not clear it. Both are private keys in the clear.
        var plaintextBytes = output.ToArray();

        try
        {
            return ParseIdentityFile(Encoding.UTF8.GetString(plaintextBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(output.GetBuffer());
        }
    }

    /// <summary>
    /// Encrypts an identity file with a passphrase using scrypt.
    /// </summary>
    /// <remarks>
    ///     <paramref name="identityFileText" /> holds private keys in the clear. The UTF-8 copy
    ///     made here is cleared; the caller's string cannot be.
    /// </remarks>
    public static byte[] EncryptIdentityFile(string identityFileText, string passphrase, bool armor = false, int workFactor = 18)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(identityFileText);

        try
        {
            using var input = new MemoryStream(plaintextBytes);
            using var output = new MemoryStream();

            AgeEncrypt.Encrypt(input, output, armor, new ScryptRecipient(passphrase, workFactor));
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }
}