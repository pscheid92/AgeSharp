using System.Text;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Recipients;

public sealed class SshRsaIdentity : IIdentity, IDisposable
{
    private const string StanzaType = "ssh-rsa";
    private const string OaepLabel = "age-encryption.org/v1/ssh-rsa";

    private readonly RsaPrivateCrtKeyParameters _privateKey;
    private readonly byte[] _sshWireBytes;
    private readonly string _tag;
    private bool _disposed;

    internal SshRsaIdentity(RsaPrivateCrtKeyParameters privateKey, byte[] sshWireBytes)
    {
        _privateKey = privateKey;
        _sshWireBytes = sshWireBytes;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    public SshRsaRecipient Recipient => new(
        new RsaKeyParameters(false, _privateKey.Modulus, _privateKey.PublicExponent),
        _sshWireBytes);

    public static SshRsaIdentity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privKey) = SshKeyParser.ParsePrivateKey(pemText);
        if (keyType != "ssh-rsa")
            throw new FormatException($"expected ssh-rsa private key, got {keyType}");

        return new SshRsaIdentity((RsaPrivateCrtKeyParameters)privKey, publicWireBytes);
    }

    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != StanzaType) return null;

        if (stanza.Args.Length != 1)
            throw new AgeHeaderException($"ssh-rsa stanza must have exactly 1 argument, got {stanza.Args.Length}");

        // Check tag matches
        if (stanza.Args[0] != _tag)
            return null;

        var oaep = new OaepEncoding(
            new RsaBlindedEngine(),
            new Sha256Digest(),
            new Sha256Digest(),
            Encoding.ASCII.GetBytes(OaepLabel));

        oaep.Init(false, _privateKey);

        try
        {
            return oaep.ProcessBlock(stanza.Body, 0, stanza.Body.Length);
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
        {
            return null;
        }
        catch (Org.BouncyCastle.Crypto.DataLengthException)
        {
            return null;
        }
    }

    // Note: RSA BigInteger fields cannot be reliably zeroed in BouncyCastle
    public void Dispose()
    {
        _disposed = true;
    }
}
