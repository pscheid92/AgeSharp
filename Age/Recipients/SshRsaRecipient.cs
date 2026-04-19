using System.Text;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Recipients;

public sealed class SshRsaRecipient : IRecipient
{
    private const int MinKeyBits = 2048;

    private readonly RsaKeyParameters _publicKey;
    private readonly string _tag;

    internal SshRsaRecipient(RsaKeyParameters publicKey, byte[] sshWireBytes)
    {
        if (publicKey.Modulus.BitLength < MinKeyBits)
            throw new ArgumentException($"RSA key must be at least {MinKeyBits} bits, got {publicKey.Modulus.BitLength}");

        _publicKey = publicKey;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    public static SshRsaRecipient Parse(string authorizedKeysLine)
    {
        var (keyType, wireBytes, pubKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        return keyType == "ssh-rsa"
            ? new SshRsaRecipient((RsaKeyParameters)pubKey, wireBytes)
            : throw new FormatException($"expected ssh-rsa, got {keyType}");
    }

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var oaep = new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest(), new Sha256Digest(), Encoding.ASCII.GetBytes(AgeProtocol.SshRsaOaepLabel));

        oaep.Init(true, _publicKey);
        var input = fileKey.ToArray();
        var body = oaep.ProcessBlock(input, 0, input.Length);

        return new Stanza(AgeProtocol.SshRsaStanzaType, [_tag], body);
    }
}