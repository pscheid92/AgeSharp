using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

namespace AgeSharp.Crypto;

/// <summary>
/// A passphrase-protected SSH private key whose public key is known without the passphrase:
/// what <see cref="AgeSharp.EncryptedSshIdentity"/> needs to tell which stanzas are its
/// own before asking for one.
/// </summary>
internal interface IProtectedSshKey
{
    /// <summary>The public key in SSH wire format.</summary>
    byte[] PublicKey { get; }

    /// <summary>
    /// Why this key cannot be decrypted here, or null if it can. Asked before the passphrase is,
    /// so nobody types one that cannot be used.
    /// </summary>
    string? WhyItCannotBeDecryptedHere();

    /// <summary>Decrypts the private key.</summary>
    /// <exception cref="CryptographicException">The passphrase is wrong, or the key file is damaged.</exception>
    /// <exception cref="FormatException">What the passphrase decrypts is not a usable key.</exception>
    (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) Unprotect(string passphrase);
}
