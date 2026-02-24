using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

public sealed class X25519Recipient : IRecipient
{
    private const string StanzaType = "X25519";
    private const string HkdfLabel = "age-encryption.org/v1/X25519";
    private const string Hrp = "age";

    private readonly X25519PublicKeyParameters _publicKey;

    internal X25519Recipient(X25519PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
    }

    public static X25519Recipient Parse(string s)
    {
        var (hrp, data) = Bech32.Decode(s);
        if (hrp != Hrp)
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");
        if (data.Length != 32)
            throw new FormatException($"X25519 public key must be 32 bytes, got {data.Length}");

        // Must be lowercase
        if (s != s.ToLowerInvariant())
            throw new FormatException("age recipient must be lowercase");

        return new X25519Recipient(new X25519PublicKeyParameters(data));
    }

    public override string ToString()
    {
        return Bech32.Encode(Hrp, _publicKey.GetEncoded());
    }

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Generate ephemeral X25519 key pair
        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // DH: ephemeral × recipient
        var agreement = new X25519Agreement();
        agreement.Init(ephemeral);
        var sharedSecret = new byte[agreement.AgreementSize];
        try
        {
            agreement.CalculateAgreement(_publicKey, sharedSecret, 0);
        }
        catch (InvalidOperationException)
        {
            throw new AgeException("X25519 key agreement failed (shared secret is zero)");
        }

        // BouncyCastle may not reject all low-order points — check for all-zero shared secret
        if (sharedSecret.All(b => b == 0))
            throw new AgeException("X25519 key agreement failed (shared secret is zero)");

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = _publicKey.GetEncoded();
        var salt = new byte[32 + 32];
        ephPubBytes.CopyTo(salt, 0);
        recipientPubBytes.CopyTo(salt, 32);

        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, HkdfLabel, 32);

        try
        {
            // Encrypt file key with ChaCha20-Poly1305, zero nonce
            var zeroNonce = new byte[12];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);

            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(StanzaType, [ephPubB64], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}
