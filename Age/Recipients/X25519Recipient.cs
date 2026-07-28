using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

/// <summary>
/// A native age X25519 recipient — the public half of an age key pair
/// (<c>age1…</c>), used to encrypt. Instances are immutable and safe to share.
/// </summary>
public sealed class X25519Recipient : IRecipient
{
    private const string Hrp = "age";
    private const int KeySize = 32;

    private readonly X25519PublicKeyParameters _publicKey;

    internal X25519Recipient(X25519PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
    }

    /// <summary>Parses a bech32-encoded recipient (<c>age1…</c>, lowercase).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 recipient.</exception>
    public static X25519Recipient Parse(string s)
    {
        var (hrp, data) = Bech32.Decode(s);
        
        if (hrp != Hrp)
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");
        
        if (data.Length != KeySize)
            throw new FormatException($"X25519 public key must be {KeySize} bytes, got {data.Length}");

        if (s != s.ToLowerInvariant())
            throw new FormatException("age recipient must be lowercase");

        return new X25519Recipient(new X25519PublicKeyParameters(data));
    }

    /// <summary>Returns the bech32-encoded recipient string (<c>age1…</c>).</summary>
    public override string ToString() =>
        Bech32.Encode(Hrp, _publicKey.GetEncoded());

    /// <summary>Wraps the file key for this recipient using ephemeral X25519 + ChaCha20-Poly1305.</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // DH: ephemeral × recipient. A recipient parsed from a hostile age1… string can carry a
        // low-order point, so this is guarded on the encrypt side too.
        var sharedSecret = new byte[CryptoHelper.X25519SharedSecretSize];
        CryptoHelper.X25519Agree(ephemeral, _publicKey, sharedSecret);

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = _publicKey.GetEncoded();
        var salt = (byte[])[.. ephPubBytes, .. recipientPubBytes];

        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.X25519HkdfLabel, KeySize);

        try
        {
            // Encrypt file key with ChaCha20-Poly1305, zero nonce
            var zeroNonce = new byte[12];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);

            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(AgeProtocol.X25519StanzaType, [ephPubB64], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}