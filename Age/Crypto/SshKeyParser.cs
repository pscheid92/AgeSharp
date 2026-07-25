using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;

namespace AgeSharp.Crypto;

internal static class SshKeyParser
{
    private const int FingerprintLength = 4;

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

    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) ParsePrivateKey(
        string pemText)
    {
        AsymmetricKeyParameter privateKey;

        if (pemText.Contains("BEGIN OPENSSH PRIVATE KEY"))
        {
            var pemReader = new PemReader(new StringReader(pemText));
            var pemObject = Guard("invalid PEM structure", pemReader.ReadPemObject)
                            ?? throw new AgeFormatException("failed to read PEM object");

            // Also covers passphrase-protected keys, which BouncyCastle rejects.
            privateKey = Guard("invalid OpenSSH private key",
                () => OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(pemObject.Content));
        }
        else
        {
            var pemReader = new PemReader(new StringReader(pemText));
            var obj = Guard("invalid PEM structure", pemReader.ReadObject);

            privateKey = obj switch
            {
                AsymmetricCipherKeyPair kp => kp.Private,
                AsymmetricKeyParameter { IsPrivate: true } akp => akp,
                _ => throw new AgeFormatException("PEM does not contain a private key")
            };
        }

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

    // Four bytes of SHA-256 over the public key, identifying which SSH key a stanza is for.
    // This is why ssh-* stanzas are linkable to a known recipient and native age ones are not.
    public static string ComputeTag(byte[] wireBytes)
    {
        var hash = SHA256.HashData(wireBytes);
        return Base64Unpadded.Encode(hash.AsSpan(0, FingerprintLength));
    }

    // BouncyCastle and the BCL throw many exception types here; all mean unparseable input.
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