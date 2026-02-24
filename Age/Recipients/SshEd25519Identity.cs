using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Recipients;

public sealed class SshEd25519Identity : IIdentity, IDisposable
{
    private const string StanzaType = "ssh-ed25519";
    private const string HkdfLabel = "age-encryption.org/v1/ssh-ed25519";

    private readonly byte[] _x25519PrivateKey;
    private readonly byte[] _x25519PublicKey;
    private readonly byte[] _sshWireBytes;
    private readonly string _tag;
    private bool _disposed;

    internal SshEd25519Identity(byte[] x25519PrivateKey, byte[] x25519PublicKey, byte[] sshWireBytes)
    {
        _x25519PrivateKey = x25519PrivateKey;
        _x25519PublicKey = x25519PublicKey;
        _sshWireBytes = sshWireBytes;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    public SshEd25519Recipient Recipient => new(_sshWireBytes, _x25519PublicKey);

    public static SshEd25519Identity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privKey) = SshKeyParser.ParsePrivateKey(pemText);
        if (keyType != "ssh-ed25519")
            throw new FormatException($"expected ssh-ed25519 private key, got {keyType}");

        var ed25519Priv = (Ed25519PrivateKeyParameters)privKey;

        // Convert Ed25519 private key seed → X25519 private key
        var x25519Priv = Ed25519Converter.PrivateKeyToX25519(ed25519Priv.GetEncoded());

        // Derive X25519 public key from the X25519 private key
        var x25519PrivParam = new X25519PrivateKeyParameters(x25519Priv);
        var x25519Pub = x25519PrivParam.GeneratePublicKey().GetEncoded();

        return new SshEd25519Identity(x25519Priv, x25519Pub, publicWireBytes);
    }

    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != StanzaType) return null;

        if (stanza.Args.Length != 2)
            throw new AgeHeaderException($"ssh-ed25519 stanza must have exactly 2 arguments, got {stanza.Args.Length}");

        // Check tag matches
        var stanzaTag = stanza.Args[0];
        if (stanzaTag != _tag)
            return null;

        // Decode ephemeral public key
        byte[] ephPubBytes;
        try
        {
            ephPubBytes = Base64Unpadded.Decode(stanza.Args[1]);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"invalid ssh-ed25519 ephemeral key encoding: {ex.Message}", ex);
        }

        if (ephPubBytes.Length != 32)
            throw new AgeHeaderException($"ssh-ed25519 ephemeral key must be 32 bytes, got {ephPubBytes.Length}");

        if (stanza.Body.Length != 32) // 16 bytes file key + 16 bytes tag
            throw new AgeHeaderException($"ssh-ed25519 stanza body must be 32 bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privKey = new X25519PrivateKeyParameters(_x25519PrivateKey);

        // rawSS = X25519.ScalarMult(_x25519PrivateKey, ephPub)
        var agreement = new X25519Agreement();
        agreement.Init(privKey);
        var rawSS = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(ephPub, rawSS, 0);

        // tweak = HKDF(ikm=[], salt=sshWireBytes, info=label, 32)
        var tweak = CryptoHelper.HkdfDerive([], _sshWireBytes, HkdfLabel, 32);

        // tweakedSS = X25519.ScalarMult(tweak, rawSS)
        var tweakPriv = new X25519PrivateKeyParameters(tweak);
        var rawSSPub = new X25519PublicKeyParameters(rawSS);
        var tweakAgreement = new X25519Agreement();
        tweakAgreement.Init(tweakPriv);
        var tweakedSS = new byte[tweakAgreement.AgreementSize];
        tweakAgreement.CalculateAgreement(rawSSPub, tweakedSS, 0);

        // wrapKey = HKDF(ikm=tweakedSS, salt=ephPub||convertedKey, info=label, 32)
        var salt = new byte[32 + 32];
        ephPubBytes.CopyTo(salt, 0);
        _x25519PublicKey.CopyTo(salt, 32);
        var wrapKey = CryptoHelper.HkdfDerive(tweakedSS, salt, HkdfLabel, 32);

        try
        {
            var zeroNonce = new byte[12];
            return CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(tweakedSS);
            CryptographicOperations.ZeroMemory(rawSS);
            CryptographicOperations.ZeroMemory(tweak);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_x25519PrivateKey);
    }
}
