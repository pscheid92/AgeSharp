using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

public sealed class X25519Identity : IIdentity, IDisposable
{
    private const string StanzaType = "X25519";
    private const string HkdfLabel = "age-encryption.org/v1/X25519";
    private const string Hrp = "AGE-SECRET-KEY-";

    private readonly byte[] _rawPrivateKey;
    private bool _disposed;

    private X25519Identity(byte[] rawPrivateKey)
    {
        _rawPrivateKey = rawPrivateKey;
    }

    public X25519Recipient Recipient => new(PublicKeyParams);

    internal X25519PublicKeyParameters PublicKeyParams
    {
        get
        {
            var priv = new X25519PrivateKeyParameters(_rawPrivateKey);
            return priv.GeneratePublicKey();
        }
    }

    public static X25519Identity Generate()
    {
        var priv = new X25519PrivateKeyParameters(new SecureRandom());
        var raw = new byte[32];
        Array.Copy(priv.GetEncoded(), raw, 32);
        return new X25519Identity(raw);
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

        var raw = new byte[32];
        Array.Copy(data, raw, 32);
        CryptographicOperations.ZeroMemory(data);
        return new X25519Identity(raw);
    }

    public override string ToString()
    {
        var rawCopy = new byte[32];
        Array.Copy(_rawPrivateKey, rawCopy, 32);
        var result = Bech32.Encode(Hrp, rawCopy).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(rawCopy);
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

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privKey = new X25519PrivateKeyParameters(_rawPrivateKey);

        // DH: identity × ephemeral
        var agreement = new X25519Agreement();
        agreement.Init(privKey);
        var sharedSecret = new byte[agreement.AgreementSize];
        try
        {
            agreement.CalculateAgreement(ephPub, sharedSecret, 0);
        }
        catch (InvalidOperationException)
        {
            throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)");
        }

        // BouncyCastle may not reject all low-order points — check for all-zero shared secret
        if (sharedSecret.All(b => b == 0))
            throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)");

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = PublicKeyParams.GetEncoded();
        var salt = new byte[32 + 32];
        ephPubBytes.CopyTo(salt, 0);
        recipientPubBytes.CopyTo(salt, 32);

        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, HkdfLabel, 32);

        try
        {
            // Decrypt file key
            var zeroNonce = new byte[12];
            var fileKey = CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body);
            if (fileKey == null)
            {
                // AEAD failure → wrong recipient, not our stanza
                return null;
            }
            return fileKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_rawPrivateKey);
    }
}
