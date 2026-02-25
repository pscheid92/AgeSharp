using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

public sealed class SshEd25519Recipient : IRecipient
{
    private const string StanzaType = "ssh-ed25519";
    private const string HkdfLabel = "age-encryption.org/v1/ssh-ed25519";
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

    public static SshEd25519Recipient Parse(string authorizedKeysLine)
    {
        var (keyType, wireBytes, pubKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        if (keyType != "ssh-ed25519")
            throw new FormatException($"expected ssh-ed25519, got {keyType}");

        var ed25519Pub = (Ed25519PublicKeyParameters)pubKey;
        var x25519Pub = Ed25519Converter.PublicKeyToX25519(ed25519Pub.GetEncoded());
        return new SshEd25519Recipient(wireBytes, x25519Pub);
    }

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Compute tweak = HKDF(ikm=[], salt=sshWireBytes, info=label, 32)
        var tweak = CryptoHelper.HkdfDerive([], _sshWireBytes, HkdfLabel, KeySize);

        // tweakedKey = X25519.ScalarMult(tweak, _x25519PublicKey)
        var tweakPrivate = new X25519PrivateKeyParameters(tweak);
        var recipientPub = new X25519PublicKeyParameters(_x25519PublicKey);
        var agreement = new X25519Agreement();
        
        agreement.Init(tweakPrivate);
        var tweakedKey = new byte[agreement.AgreementSize];
        
        agreement.CalculateAgreement(recipientPub, tweakedKey, 0);

        // Generate ephemeral X25519 key pair
        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // sharedSecret = X25519.ScalarMult(ephSecret, tweakedKey)
        // We need to do DH(ephemeral, tweakedKey) but tweakedKey is a point, not a public key parameter
        // Use the tweakedKey as a public key for the agreement
        var tweakedPub = new X25519PublicKeyParameters(tweakedKey);
        var ephAgreement = new X25519Agreement();
        ephAgreement.Init(ephemeral);
        var sharedSecret = new byte[ephAgreement.AgreementSize];
        ephAgreement.CalculateAgreement(tweakedPub, sharedSecret, 0);

        // wrapKey = HKDF(ikm=sharedSecret, salt=ephPub||convertedKey, info=label, 32)
        var salt = (byte[])[.. ephPubBytes, .. _x25519PublicKey];
        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, HkdfLabel, KeySize);

        try
        {
            var zeroNonce = new byte[NonceSize];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(StanzaType, [_tag, ephPubB64], body);
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