using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

/// <summary>
/// A recipient backed by an ssh-ed25519 public key (an <c>authorized_keys</c>
/// line), encrypting via the age <c>ssh-ed25519</c> recipient type.
/// </summary>
public sealed class SshEd25519Recipient : IRecipient
{
    private const int KeySize = 32;
    private const int NonceSize = 12;

    private readonly byte[] _sshWireBytes;
    private readonly byte[] _x25519PublicKey;
    private readonly string _tag;

    internal SshEd25519Recipient(byte[] sshWireBytes, byte[] x25519PublicKey)
    {
        _sshWireBytes = sshWireBytes;
        _x25519PublicKey = x25519PublicKey;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    /// <summary>Parses an <c>ssh-ed25519 AAAA…</c> public key line.</summary>
    /// <exception cref="FormatException">The line is not a valid ssh-ed25519 public key.</exception>
    public static SshEd25519Recipient Parse(string authorizedKeysLine)
    {
        var (keyType, wireBytes, pubKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        if (keyType != "ssh-ed25519")
            throw new FormatException($"expected ssh-ed25519, got {keyType}");

        var ed25519Pub = (Ed25519PublicKeyParameters)pubKey;
        var x25519Pub = Ed25519Converter.PublicKeyToX25519(ed25519Pub.GetEncoded());
        return new SshEd25519Recipient(wireBytes, x25519Pub);
    }

    /// <summary>Wraps the file key for this SSH key via tweaked X25519 + ChaCha20-Poly1305.</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Compute tweak = HKDF(ikm=[], salt=sshWireBytes, info=label, 32)
        var tweak = CryptoHelper.HkdfDerive([], _sshWireBytes, AgeProtocol.SshEd25519HkdfLabel, KeySize);

        // tweakedKey = X25519.ScalarMult(tweak, _x25519PublicKey)
        var tweakPrivate = new X25519PrivateKeyParameters(tweak);
        var recipientPub = new X25519PublicKeyParameters(_x25519PublicKey);
        var tweakedKey = new byte[CryptoHelper.X25519SharedSecretSize];
        CryptoHelper.X25519Agree(tweakPrivate, recipientPub, tweakedKey);

        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // sharedSecret = X25519.ScalarMult(ephSecret, tweakedKey). tweakedKey is a point rather
        // than a public key parameter, so it is wrapped as one for the agreement.
        var tweakedPub = new X25519PublicKeyParameters(tweakedKey);
        var sharedSecret = new byte[CryptoHelper.X25519SharedSecretSize];
        CryptoHelper.X25519Agree(ephemeral, tweakedPub, sharedSecret);

        // wrapKey = HKDF(ikm=sharedSecret, salt=ephPub||convertedKey, info=label, 32)
        var salt = (byte[])[.. ephPubBytes, .. _x25519PublicKey];
        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.SshEd25519HkdfLabel, KeySize);

        try
        {
            var zeroNonce = new byte[NonceSize];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(AgeProtocol.SshEd25519StanzaType, [_tag, ephPubB64], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(tweakedKey);
            CryptographicOperations.ZeroMemory(tweak);
        }
    }
}