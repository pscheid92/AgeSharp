using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Format;
using NSec.Cryptography;

namespace Age.Recipients;

public sealed class X25519Recipient : IRecipient
{
    private const string StanzaType = "X25519";
    private const string HkdfLabel = "age-encryption.org/v1/X25519";
    private const string Hrp = "age";

    private readonly PublicKey _publicKey;

    internal X25519Recipient(PublicKey publicKey)
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

        var pk = PublicKey.Import(KeyAgreementAlgorithm.X25519, data, KeyBlobFormat.RawPublicKey);
        if (pk == null)
            throw new FormatException("invalid X25519 public key");
        return new X25519Recipient(pk);
    }

    public override string ToString()
    {
        var rawPk = _publicKey.Export(KeyBlobFormat.RawPublicKey);
        return Bech32.Encode(Hrp, rawPk);
    }

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Generate ephemeral X25519 key pair
        using var ephemeral = NSec.Cryptography.Key.Create(KeyAgreementAlgorithm.X25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var ephPubBytes = ephemeral.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        // DH: ephemeral × recipient
        using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(ephemeral, _publicKey);
        if (sharedSecret == null)
            throw new AgeException("X25519 key agreement failed (shared secret is zero)");

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = _publicKey.Export(KeyBlobFormat.RawPublicKey);
        var salt = new byte[32 + 32];
        ephPubBytes.CopyTo(salt, 0);
        recipientPubBytes.CopyTo(salt, 32);

        var hkdf = KeyDerivationAlgorithm.HkdfSha256;
        var wrapKey = hkdf.DeriveBytes(sharedSecret, salt, Encoding.ASCII.GetBytes(HkdfLabel), 32);

        try
        {
            // Encrypt file key with ChaCha20-Poly1305, zero nonce
            var aead = AeadAlgorithm.ChaCha20Poly1305;
            using var ck = NSec.Cryptography.Key.Import(aead, wrapKey, KeyBlobFormat.RawSymmetricKey);
            var zeroNonce = new byte[12];
            var body = aead.Encrypt(ck, zeroNonce, ReadOnlySpan<byte>.Empty, fileKey);

            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(StanzaType, [ephPubB64], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }
}
