using Age.Crypto;
using Age.Recipients;

namespace Age;

public static class AgeKeygen
{
    public static X25519Identity Generate() => X25519Identity.Generate();

    public static X25519Identity ParseIdentity(string s) => X25519Identity.Parse(s);

    public static X25519Recipient ParseRecipient(string s) => X25519Recipient.Parse(s);

    public static MlKem768X25519Identity GeneratePq() => MlKem768X25519Identity.Generate();

    public static MlKem768X25519Identity ParsePqIdentity(string s) => MlKem768X25519Identity.Parse(s);

    public static MlKem768X25519Recipient ParsePqRecipient(string s) => MlKem768X25519Recipient.Parse(s);

    /// <summary>
    /// Parses an SSH public key from an authorized_keys line and returns the appropriate recipient.
    /// Supports ssh-ed25519 and ssh-rsa key types.
    /// </summary>
    public static IRecipient ParseSshRecipient(string authorizedKeysLine)
    {
        var (keyType, wireBytes, pubKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);
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
}
