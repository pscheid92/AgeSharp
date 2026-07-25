using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;

namespace AgeSharp.Crypto;

internal static class SshKeyParser
{
    // age spec: SSH stanza tags use the first 4 bytes of SHA-256(publicKeyWireBytes)
    private const int FingerprintLength = 4;

    /// <summary>
    ///     Parses an SSH public key from an authorized_keys line.
    ///     Returns (keyType, wireBytes, publicKeyParameter).
    ///     wireBytes is the raw SSH wire format bytes (the base64-decoded middle section).
    /// </summary>
    public static (string keyType, byte[] wireBytes, AsymmetricKeyParameter publicKey) ParsePublicKey(
        string authorizedKeysLine)
    {
        var parts = authorizedKeysLine.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new AgeFormatException("invalid authorized_keys line: expected at least 2 fields");

        var keyType = parts[0];
        if (keyType != "ssh-ed25519" && keyType != "ssh-rsa")
            throw new AgeFormatException($"unsupported SSH key type: {keyType}");

        var wireBytes = Guard("invalid base64 in authorized_keys line",
            () => Convert.FromBase64String(parts[1]));

        var publicKey = Guard("invalid SSH public key data",
            () => OpenSshPublicKeyUtilities.ParsePublicKey(wireBytes));

        return (keyType, wireBytes, publicKey);
    }

    /// <summary>
    ///     Parses an SSH private key from PEM text.
    ///     Returns (keyType, publicWireBytes, privateKeyParameter).
    ///     Supports OpenSSH format (-----BEGIN OPENSSH PRIVATE KEY-----) and PKCS#8/PKCS#1.
    /// </summary>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) ParsePrivateKey(
        string pemText)
    {
        AsymmetricKeyParameter privateKey;

        if (pemText.Contains("BEGIN OPENSSH PRIVATE KEY"))
        {
            // OpenSSH format: extract the base64 blob and parse
            var pemReader = new PemReader(new StringReader(pemText));
            var pemObject = Guard("invalid PEM structure", pemReader.ReadPemObject)
                            ?? throw new AgeFormatException("failed to read PEM object");

            // Also covers passphrase-protected keys, which BouncyCastle rejects
            privateKey = Guard("invalid OpenSSH private key",
                () => OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(pemObject.Content));
        }
        else
        {
            // PKCS#1 or PKCS#8 format
            var pemReader = new PemReader(new StringReader(pemText));
            var obj = Guard("invalid PEM structure", pemReader.ReadObject);

            privateKey = obj switch
            {
                AsymmetricCipherKeyPair kp => kp.Private,
                AsymmetricKeyParameter { IsPrivate: true } akp => akp,
                _ => throw new AgeFormatException("PEM does not contain a private key")
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
                throw new AgeFormatException($"unsupported private key type: {privateKey.GetType().Name}");
        }

        var publicWireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(publicKey);
        return (keyType, publicWireBytes, privateKey);
    }

    /// <summary>
    ///     Computes the SSH key fingerprint tag used in age stanzas.
    ///     tag = base64_unpadded(SHA-256(wireBytes)[:4])
    /// </summary>
    public static string ComputeTag(byte[] wireBytes)
    {
        var hash = SHA256.HashData(wireBytes);
        return Base64Unpadded.Encode(hash.AsSpan(0, FingerprintLength));
    }

    // BouncyCastle and the BCL throw a zoo of exception types on malformed
    // input (FormatException, IOException, PemException, Asn1 errors, ...);
    // inside this parser they are all one thing: unparseable input.
    private static T Guard<T>(string error, Func<T> parse)
    {
        try
        {
            return parse();
        }
        catch (Exception ex) when (ex is not AgeFormatException)
        {
            throw new AgeFormatException(error, ex);
        }
    }
}