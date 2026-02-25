using System.Text;
using Age.Crypto;
using Age.Plugin;
using Age.Recipients;

namespace Age;

public static class AgeKeygen
{
    public static X25519Identity Generate() =>
        X25519Identity.Generate();

    public static X25519Identity ParseIdentity(string s) =>
        X25519Identity.Parse(s);

    public static X25519Recipient ParseRecipient(string s) =>
        X25519Recipient.Parse(s);

    public static MlKem768X25519Identity GeneratePq() =>
        MlKem768X25519Identity.Generate();

    public static MlKem768X25519Identity ParsePqIdentity(string s) =>
        MlKem768X25519Identity.Parse(s);

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
    /// </summary>
    public static IReadOnlyList<IRecipient> ParseRecipientsFile(string text, IPluginCallbacks? callbacks = null) =>
        text.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(line => ParseRecipientLine(line, callbacks))
            .ToList();

    private static IRecipient ParseRecipientLine(string line, IPluginCallbacks? callbacks) => line switch
    {
        _ when line.StartsWith("age1pq") => MlKem768X25519Recipient.Parse(line),
        _ when line.StartsWith("age1") && line.IndexOf('1', 4) > 0 => new PluginRecipient(line, callbacks),
        _ when line.StartsWith("age1") => X25519Recipient.Parse(line),
        _ when line.StartsWith("ssh-") => ParseSshRecipient(line),
        _ => throw new FormatException($"unrecognized line in recipients file: {line}")
    };

    /// <summary>
    /// Parses a plaintext identity file containing AGE-SECRET-KEY lines, plugin identities, comments, and blank lines.
    /// </summary>
    public static IReadOnlyList<IIdentity> ParseIdentityFile(string text, IPluginCallbacks? callbacks = null)
    {
        var identities = new List<IIdentity>();

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;

            if (trimmed.StartsWith("AGE-SECRET-KEY-PQ-"))
                identities.Add(MlKem768X25519Identity.Parse(trimmed));
            else if (trimmed.StartsWith("AGE-SECRET-KEY-"))
                identities.Add(X25519Identity.Parse(trimmed));
            else if (trimmed.StartsWith("AGE-PLUGIN-"))
                identities.Add(new PluginIdentity(trimmed, callbacks));
            else
                throw new FormatException($"unrecognized line in identity file: {trimmed}");
        }

        return identities;
    }

    /// <summary>
    /// Decrypts an encrypted (passphrase-protected) identity file and parses the contained identities.
    /// </summary>
    public static IReadOnlyList<IIdentity> DecryptIdentityFile(byte[] data, string passphrase)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();

        AgeEncrypt.Decrypt(input, output, new ScryptRecipient(passphrase));
        var plaintext = Encoding.UTF8.GetString(output.ToArray());
        return ParseIdentityFile(plaintext);
    }

    /// <summary>
    /// Encrypts an identity file with a passphrase using scrypt.
    /// </summary>
    public static byte[] EncryptIdentityFile(string identityFileText, string passphrase, bool armor = false, int workFactor = 18)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(identityFileText);
        using var input = new MemoryStream(plaintextBytes);
        using var output = new MemoryStream();

        AgeEncrypt.Encrypt(input, output, armor, new ScryptRecipient(passphrase, workFactor));
        return output.ToArray();
    }
}