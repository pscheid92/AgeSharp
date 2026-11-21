using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// An SSH private key as an age identity: ssh-ed25519 or ssh-rsa, unprotected or protected by a
/// passphrase. Each method returns the identity the key file calls for: an
/// <see cref="SshEd25519Identity"/>, an <see cref="SshRsaIdentity"/>, or, for a protected key, an
/// <see cref="EncryptedSshIdentity"/> that asks for the passphrase only once a file addressed to
/// the key is decrypted.
/// </summary>
/// <remarks>
/// The passphrase is asked for as a <see cref="string"/>: the key is decrypted by SSH.NET, which
/// takes one. <see cref="Identities.ParseOne"/> reads unprotected keys too.
/// </remarks>
public static class SshIdentity
{
    /// <summary>
    /// Parses an SSH private key from PEM text and returns the appropriate identity.
    /// Supports ssh-ed25519 and ssh-rsa key types in OpenSSH, PKCS#1, or PKCS#8 format.
    /// </summary>
    /// <exception cref="FormatException">
    /// The key is malformed or of another type, or it is passphrase-protected: use
    /// <see cref="Parse(string, Func{string})"/> for a key that may be.
    /// </exception>
    public static IIdentity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privateKey) = SshKeyParser.ParsePrivateKey(pemText);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Identity.FromParsedKey(keyType, publicWireBytes, privateKey),
            "ssh-rsa" => SshRsaIdentity.FromParsedKey(keyType, publicWireBytes, privateKey),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    /// <summary>
    /// Parses an SSH private key that may be passphrase-protected. A protected key (OpenSSH
    /// format) becomes an <see cref="EncryptedSshIdentity"/>, which asks
    /// <paramref name="passphrase"/> only once a file addressed to the key is decrypted; an
    /// unprotected key is parsed as by <see cref="Parse(string)"/> and never asks.
    /// </summary>
    /// <exception cref="FormatException">
    /// The key is malformed, of another type, or protected in the legacy PEM way, which does
    /// not store its public key: use <see cref="Parse(string, string, Func{string})"/>
    /// with its <c>.pub</c> file for that. A key protected with a cipher or KDF this library
    /// does not read is accepted, and refused once a file is addressed to it, before the
    /// passphrase is asked for.
    /// </exception>
    public static IIdentity Parse(string pemText, Func<string> passphrase)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        ArgumentNullException.ThrowIfNull(passphrase);

        return SshKeyParser.ParseProtectedKey(pemText) is { } protectedKey
            ? new EncryptedSshIdentity(protectedKey, passphrase)
            : Parse(pemText);
    }

    /// <summary>
    /// Parses an SSH private key that may be passphrase-protected, together with its public
    /// key (the <c>.pub</c> file). This also reads ssh-rsa keys protected in the legacy PEM
    /// format (<c>BEGIN RSA PRIVATE KEY</c> with <c>Proc-Type: 4,ENCRYPTED</c>), which do not
    /// store their public key, as go-age does: the public key decides which files are for
    /// the key, <paramref name="passphrase"/> is asked only once one is decrypted, and the
    /// decrypted key must then match the public key. Other keys are read as by
    /// <see cref="Parse(string, Func{string})"/>, and must match the public key.
    /// </summary>
    /// <param name="pemText">The private key file.</param>
    /// <param name="publicKey">The public key file's text: an authorized_keys line.</param>
    /// <param name="passphrase">Asked for the passphrase when a file is for a protected key.</param>
    /// <exception cref="FormatException">
    /// The private or public key is malformed or of another type, the public key does not
    /// belong to a key file that names its own, or the key is encrypted PKCS#8 (not read, as
    /// in go-age). A key protected with a cipher this library does not decrypt is accepted,
    /// and refused once a file is addressed to it, before the passphrase is asked for.
    /// </exception>
    public static IIdentity Parse(string pemText, string publicKey, Func<string> passphrase)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(passphrase);

        var (publicKeyType, publicWireBytes, _) = SshKeyParser.ParsePublicKey(publicKey);

        if (LegacyPemSshKey.IsLegacyProtected(pemText))
        {
            if (publicKeyType != "ssh-rsa")
                throw new FormatException($"a legacy PEM SSH key is an ssh-rsa key, but the public key is {publicKeyType}");

            return new EncryptedSshIdentity(LegacyPemSshKey.Parse(pemText, publicWireBytes), passphrase);
        }

        if (SshKeyParser.ParseProtectedKey(pemText) is { } protectedKey)
        {
            RequireSamePublicKey(protectedKey.PublicKey, publicWireBytes);
            return new EncryptedSshIdentity(protectedKey, passphrase);
        }

        var (keyType, ownPublicKey, privateKey) = SshKeyParser.ParsePrivateKey(pemText);
        RequireSamePublicKey(ownPublicKey, publicWireBytes);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Identity.FromParsedKey(keyType, ownPublicKey, privateKey),
            "ssh-rsa" => SshRsaIdentity.FromParsedKey(keyType, ownPublicKey, privateKey),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    private static void RequireSamePublicKey(byte[] ownPublicKey, byte[] given)
    {
        if (!ownPublicKey.AsSpan().SequenceEqual(given))
            throw new FormatException("the public key does not belong to the SSH private key");
    }
}
