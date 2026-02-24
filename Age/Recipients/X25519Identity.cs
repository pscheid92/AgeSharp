using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Format;
using NSec.Cryptography;

namespace Age.Recipients;

public sealed class X25519Identity : IIdentity, IDisposable
{
    private const string StanzaType = "X25519";
    private const string HkdfLabel = "age-encryption.org/v1/X25519";
    private const string Hrp = "AGE-SECRET-KEY-";

    private readonly NSec.Cryptography.Key _privateKey;
    private bool _disposed;

    private X25519Identity(NSec.Cryptography.Key privateKey)
    {
        _privateKey = privateKey;
    }

    public X25519Recipient Recipient => new(PublicKey);

    internal PublicKey PublicKey => _privateKey.PublicKey;

    public static X25519Identity Generate()
    {
        var key = NSec.Cryptography.Key.Create(KeyAgreementAlgorithm.X25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return new X25519Identity(key);
    }

    public static X25519Identity Parse(string s)
    {
        // Must be uppercase
        if (s != s.ToUpperInvariant())
            throw new FormatException("age secret key must be uppercase");

        var (hrp, data) = Bech32.Decode(s);
        if (!string.Equals(hrp, Hrp, StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");
        if (data.Length != 32)
            throw new FormatException($"X25519 secret key must be 32 bytes, got {data.Length}");

        var key = NSec.Cryptography.Key.Import(KeyAgreementAlgorithm.X25519, data,
            KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        CryptographicOperations.ZeroMemory(data);
        return new X25519Identity(key);
    }

    public override string ToString()
    {
        var rawKey = _privateKey.Export(KeyBlobFormat.RawPrivateKey);
        var result = Bech32.Encode(Hrp, rawKey).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(rawKey);
        return result;
    }

    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != StanzaType) return null;

        if (stanza.Args.Length != 1)
            throw new AgeHeaderException($"X25519 stanza must have exactly 1 argument, got {stanza.Args.Length}");

        byte[] ephPubBytes;
        try
        {
            ephPubBytes = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"invalid X25519 ephemeral key encoding: {ex.Message}", ex);
        }

        if (ephPubBytes.Length != 32)
            throw new AgeHeaderException($"X25519 ephemeral key must be 32 bytes, got {ephPubBytes.Length}");

        if (stanza.Body.Length != 32) // 16 bytes file key + 16 bytes tag
            throw new AgeHeaderException($"X25519 stanza body must be 32 bytes, got {stanza.Body.Length}");

        var ephPub = PublicKey.Import(KeyAgreementAlgorithm.X25519, ephPubBytes, KeyBlobFormat.RawPublicKey);
        if (ephPub == null)
            throw new AgeHeaderException("invalid X25519 ephemeral public key");

        // DH: identity × ephemeral
        using var sharedSecret = KeyAgreementAlgorithm.X25519.Agree(_privateKey, ephPub);
        if (sharedSecret == null)
            throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)");

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = _privateKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var salt = new byte[32 + 32];
        ephPubBytes.CopyTo(salt, 0);
        recipientPubBytes.CopyTo(salt, 32);

        var hkdf = KeyDerivationAlgorithm.HkdfSha256;
        var wrapKey = hkdf.DeriveBytes(sharedSecret, salt, Encoding.ASCII.GetBytes(HkdfLabel), 32);

        try
        {
            // Decrypt file key
            var aead = AeadAlgorithm.ChaCha20Poly1305;
            using var ck = NSec.Cryptography.Key.Import(aead, wrapKey, KeyBlobFormat.RawSymmetricKey);
            var zeroNonce = new byte[12];

            try
            {
                return aead.Decrypt(ck, zeroNonce, ReadOnlySpan<byte>.Empty, stanza.Body);
            }
            catch (CryptographicException)
            {
                // AEAD failure → wrong recipient, not our stanza
                return null;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _privateKey.Dispose();
    }
}
