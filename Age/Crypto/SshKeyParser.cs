using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

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

        var publicKey = FromBouncyCastle(() => OpenSshPublicKeyUtilities.ParsePublicKey(wireBytes), $"invalid {keyType} public key");

        // The line names its type twice, in the first field and inside the key data. Callers
        // dispatch on the first and cast what the second produced, so they must agree.
        var dataType = KeyTypeOf(publicKey);
        if (dataType != keyType)
            throw new FormatException($"authorized_keys line says {keyType}, but its key data is {dataType ?? "another key type"}");

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
            var pemObject = FromBouncyCastle(() => new PemReader(new StringReader(pemText)).ReadPemObject(), "invalid PEM")
                            ?? throw new FormatException("failed to read PEM object");

            if (IsPassphraseProtected(pemObject.Content))
                throw PassphraseProtected();

            privateKey = FromBouncyCastle(() => OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(pemObject.Content), "invalid OpenSSH private key");
        }
        else
        {
            object? obj;

            try
            {
                obj = FromBouncyCastle(() => new PemReader(new StringReader(pemText)).ReadObject(), "invalid PEM private key");
            }
            catch (FormatException ex) when (ex.InnerException is PasswordException || pemText.Contains("BEGIN ENCRYPTED PRIVATE KEY"))
            {
                // PKCS#1 with Proc-Type: 4,ENCRYPTED raises PasswordException; encrypted PKCS#8
                // fails inside BouncyCastle's decoder with a message that never says why.
                throw PassphraseProtected();
            }

            privateKey = obj switch
            {
                AsymmetricCipherKeyPair kp => kp.Private,
                AsymmetricKeyParameter { IsPrivate: true } akp => akp,
                _ => throw new FormatException("PEM does not contain a private key")
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
                throw new FormatException($"unsupported private key type: {privateKey.GetType().Name}");
        }

        var publicWireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(publicKey);
        return (keyType, publicWireBytes, privateKey);
    }

    private static string? KeyTypeOf(AsymmetricKeyParameter key) => key switch
    {
        Ed25519PublicKeyParameters => "ssh-ed25519",
        RsaKeyParameters { IsPrivate: false } => "ssh-rsa",
        _ => null,
    };

    /// <summary>
    /// Whether an openssh-key-v1 blob names a cipher other than "none". The cipher is the first
    /// field after the magic, so this is decidable before anything encrypted is touched. A blob
    /// too short to say is left for the parser to reject as malformed.
    /// </summary>
    private static bool IsPassphraseProtected(ReadOnlySpan<byte> blob)
    {
        ReadOnlySpan<byte> magic = "openssh-key-v1\0"u8;

        if (!blob.StartsWith(magic) || blob.Length < magic.Length + 4)
            return false;

        var cipherLength = BinaryPrimitives.ReadUInt32BigEndian(blob[magic.Length..]);
        var cipher = blob[(magic.Length + 4)..];

        return cipherLength <= (uint)cipher.Length && !cipher[..(int)cipherLength].SequenceEqual("none"u8);
    }

    // go-age prompts for the passphrase; BouncyCastle cannot decrypt these keys, so say so plainly.
    private static FormatException PassphraseProtected() =>
        new("passphrase-protected SSH keys are not supported; " +
            "remove the passphrase from a copy with ssh-keygen -p, and keep that copy safe");

    /// <summary>
    /// Runs a BouncyCastle parse over untrusted input and reports its failures as
    /// <see cref="FormatException"/>. BouncyCastle signals malformed keys with whatever its
    /// decoder hit — argument, range, state and I/O exceptions among them — and none of those
    /// may escape a parser documented to throw FormatException.
    /// </summary>
    private static T FromBouncyCastle<T>(Func<T> parse, string what)
    {
        try
        {
            return parse();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException
                                       or IndexOutOfRangeException or InvalidCastException)
        {
            throw new FormatException($"{what}: {ex.Message}", ex);
        }
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