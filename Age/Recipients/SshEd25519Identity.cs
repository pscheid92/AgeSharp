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
    private const int KeySize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _x25519PrivateKey;
    private readonly byte[] _x25519PublicKey;
    private readonly byte[] _sshWireBytes;
    private readonly string _tag;
    private bool _disposed;

    private SshEd25519Identity(byte[] x25519PrivateKey, byte[] x25519PublicKey, byte[] sshWireBytes)
    {
        _x25519PrivateKey = x25519PrivateKey;
        _x25519PublicKey = x25519PublicKey;
        _sshWireBytes = sshWireBytes;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    public SshEd25519Recipient Recipient =>
        new(_sshWireBytes, _x25519PublicKey);

    public static SshEd25519Identity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privateKey) = SshKeyParser.ParsePrivateKey(pemText);

        if (keyType != "ssh-ed25519")
            throw new FormatException($"expected ssh-ed25519 private key, got {keyType}");

        var ed25519Private = (Ed25519PrivateKeyParameters)privateKey;

        // Convert Ed25519 private key seed → X25519 private key
        var x25519Private = Ed25519Converter.PrivateKeyToX25519(ed25519Private.GetEncoded());

        // Derive X25519 public key from the X25519 private key
        var x25519PrivateParam = new X25519PrivateKeyParameters(x25519Private);
        var x25519Pub = x25519PrivateParam.GeneratePublicKey().GetEncoded();

        return new SshEd25519Identity(x25519Private, x25519Pub, publicWireBytes);
    }

    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != StanzaType)
            return null;

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

        if (ephPubBytes.Length != KeySize)
            throw new AgeHeaderException($"ssh-ed25519 ephemeral key must be {KeySize} bytes, got {ephPubBytes.Length}");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeHeaderException($"ssh-ed25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privateKey = new X25519PrivateKeyParameters(_x25519PrivateKey);

        // rawSS = X25519.ScalarMult(_x25519PrivateKey, ephPub)
        var agreement = new X25519Agreement();
        agreement.Init(privateKey);

        var rawSS = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(ephPub, rawSS, 0);

        // tweak = HKDF(ikm=[], salt=sshWireBytes, info=label, 32)
        var tweak = CryptoHelper.HkdfDerive([], _sshWireBytes, HkdfLabel, KeySize);

        // tweakedSS = X25519.ScalarMult(tweak, rawSS)
        var tweakPrivate = new X25519PrivateKeyParameters(tweak);
        var rawSSPub = new X25519PublicKeyParameters(rawSS);

        var tweakAgreement = new X25519Agreement();
        tweakAgreement.Init(tweakPrivate);

        var tweakedSS = new byte[tweakAgreement.AgreementSize];
        tweakAgreement.CalculateAgreement(rawSSPub, tweakedSS, 0);

        // wrapKey = HKDF(ikm=tweakedSS, salt=ephPub||convertedKey, info=label, 32)
        var salt = (byte[])[.. ephPubBytes, .. _x25519PublicKey];
        var wrapKey = CryptoHelper.HkdfDerive(tweakedSS, salt, HkdfLabel, KeySize);

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
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_x25519PrivateKey);
    }
}