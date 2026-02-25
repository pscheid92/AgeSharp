using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;

namespace Age.Crypto;

internal static class SshKeyParser
{
    // age spec: SSH stanza tags use the first 4 bytes of SHA-256(publicKeyWireBytes)
    private const int FingerprintLength = 4;
    /// <summary>
    /// Parses an SSH public key from an authorized_keys line.
    /// Returns (keyType, wireBytes, publicKeyParameter).
    /// wireBytes is the raw SSH wire format bytes (the base64-decoded middle section).
    /// </summary>
    public static (string keyType, byte[] wireBytes, AsymmetricKeyParameter publicKey) ParsePublicKey(string authorizedKeysLine)
    {
        var parts = authorizedKeysLine.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new FormatException("invalid authorized_keys line: expected at least 2 fields");

        var keyType = parts[0];
        if (keyType != "ssh-ed25519" && keyType != "ssh-rsa")
            throw new FormatException($"unsupported SSH key type: {keyType}");

        byte[] wireBytes;
        try
        {
            wireBytes = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("invalid base64 in authorized_keys line", ex);
        }

        var publicKey = OpenSshPublicKeyUtilities.ParsePublicKey(wireBytes);
        return (keyType, wireBytes, publicKey);
    }

    /// <summary>
    /// Parses an SSH private key from PEM text.
    /// Returns (keyType, publicWireBytes, privateKeyParameter).
    /// Supports OpenSSH format (-----BEGIN OPENSSH PRIVATE KEY-----) and PKCS#8/PKCS#1.
    /// </summary>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) ParsePrivateKey(string pemText)
    {
        AsymmetricKeyParameter privateKey;

        if (pemText.Contains("BEGIN OPENSSH PRIVATE KEY"))
        {
            // OpenSSH format: extract the base64 blob and parse
            var pemReader = new PemReader(new StringReader(pemText));
            var pemObject = pemReader.ReadPemObject();
            if (pemObject == null)
                throw new FormatException("failed to read PEM object");

            privateKey = OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(pemObject.Content);
        }
        else
        {
            // PKCS#1 or PKCS#8 format
            var pemReader = new PemReader(new StringReader(pemText));
            var obj = pemReader.ReadObject();

            privateKey = obj switch
            {
                AsymmetricCipherKeyPair kp => kp.Private,
                AsymmetricKeyParameter { IsPrivate: true } akp => akp,
                _ => throw new FormatException("PEM does not contain a private key")
            };
        }

        // Derive public key and encode to SSH wire format
        AsymmetricKeyParameter publicKey;
        string keyType;

        switch (privateKey)
        {
            case Ed25519PrivateKeyParameters ed25519Private:
                publicKey = ed25519Private.GeneratePublicKey();
                keyType = "ssh-ed25519";
                break;
            case RsaPrivateCrtKeyParameters rsaPrivate:
                publicKey = new RsaKeyParameters(false, rsaPrivate.Modulus, rsaPrivate.PublicExponent);
                keyType = "ssh-rsa";
                break;
            default:
                throw new FormatException($"unsupported private key type: {privateKey.GetType().Name}");
        }

        var publicWireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(publicKey);
        return (keyType, publicWireBytes, privateKey);
    }

    /// <summary>
    /// Computes the SSH key fingerprint tag used in age stanzas.
    /// tag = base64_unpadded(SHA-256(wireBytes)[:4])
    /// </summary>
    public static string ComputeTag(byte[] wireBytes)
    {
        var hash = SHA256.HashData(wireBytes);
        return Base64Unpadded.Encode(hash.AsSpan(0, FingerprintLength));
    }
}