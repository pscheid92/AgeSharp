using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
namespace AgeSharp;

/// <summary>
/// SSH private keys, including passphrase-protected ones, and passphrase-protected identity
/// files. Recipients and identities of every other kind parse through <see cref="Recipients"/>,
/// <see cref="Identities"/> and the key types themselves.
/// </summary>
/// <remarks>What is left here moves to the key types themselves with the key-material rework.</remarks>
public static class AgeKeygen
{
    /// <summary>
    /// Parses an SSH private key from PEM text and returns the appropriate identity.
    /// Supports ssh-ed25519 and ssh-rsa key types in OpenSSH, PKCS#1, or PKCS#8 format.
    /// </summary>
    /// <exception cref="FormatException">
    /// The key is malformed or of another type, or it is passphrase-protected: use
    /// <see cref="ParseSshIdentity(string, Func{string})"/> for a key that may be.
    /// </exception>
    public static IIdentity ParseSshIdentity(string pemText)
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
    /// unprotected key is parsed as by <see cref="ParseSshIdentity(string)"/> and never asks.
    /// </summary>
    /// <exception cref="FormatException">
    /// The key is malformed, of another type, or protected in the legacy PEM way, which does
    /// not store its public key: use <see cref="ParseSshIdentity(string, string, Func{string})"/>
    /// with its <c>.pub</c> file for that. A key protected with a cipher or KDF this library
    /// does not read is accepted, and refused once a file is addressed to it, before the
    /// passphrase is asked for.
    /// </exception>
    public static IIdentity ParseSshIdentity(string pemText, Func<string> passphrase)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        ArgumentNullException.ThrowIfNull(passphrase);

        return SshKeyParser.ParseProtectedKey(pemText) is { } protectedKey
            ? new EncryptedSshIdentity(protectedKey, passphrase)
            : ParseSshIdentity(pemText);
    }

    /// <summary>
    /// Parses an SSH private key that may be passphrase-protected, together with its public
    /// key (the <c>.pub</c> file). This also reads ssh-rsa keys protected in the legacy PEM
    /// format (<c>BEGIN RSA PRIVATE KEY</c> with <c>Proc-Type: 4,ENCRYPTED</c>), which do not
    /// store their public key, as go-age does: the public key decides which files are for
    /// the key, <paramref name="passphrase"/> is asked only once one is decrypted, and the
    /// decrypted key must then match the public key. Other keys are read as by
    /// <see cref="ParseSshIdentity(string, Func{string})"/>, and must match the public key.
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
    public static IIdentity ParseSshIdentity(string pemText, string publicKey, Func<string> passphrase)
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

    /// <summary>
    /// Decrypts an encrypted (passphrase-protected) identity file and parses the contained identities.
    /// </summary>
    /// <remarks>
    ///     The decrypted file contains <c>AGE-SECRET-KEY-1…</c> lines in the clear. The byte
    ///     copies are cleared here; the <see cref="string" /> they are decoded into cannot be,
    ///     because <see cref="Identities.Parse" /> takes a string.
    ///     Treat this as reducing the exposure rather than eliminating it.
    /// </remarks>
    public static IIdentity[] DecryptIdentityFile(byte[] data, string passphrase)
    {
        using var input = new MemoryStream(data);

        // Sized up front: the plaintext is always shorter than the file, so the buffer never
        // grows. A growing MemoryStream abandons each outgrown buffer with a copy of the private
        // keys in it, where the clearing below cannot reach.
        using var output = new MemoryStream(data.Length);

        using var passphraseIdentity = new ScryptRecipient(passphrase);
        new Identities(passphraseIdentity).Decrypt(input, output);

        // ToArray copies out, and the MemoryStream's own buffer keeps the plaintext too —
        // Dispose does not clear it. Both are private keys in the clear.
        var plaintextBytes = output.ToArray();

        try
        {
            // The set is not disposed: the identities are handed to the caller, who owns them.
            return [.. Identities.Parse(Encoding.UTF8.GetString(plaintextBytes))];
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

            new Recipients(new ScryptRecipient(passphrase, workFactor)).Encrypt(input, output, new AgeEncryptOptions { Armor = armor });
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }
}