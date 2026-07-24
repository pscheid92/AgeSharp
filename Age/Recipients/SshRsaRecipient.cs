using System.Diagnostics.CodeAnalysis;
using System.Text;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Recipients;

/// <summary>
/// A recipient backed by an ssh-rsa public key (an <c>authorized_keys</c> line,
/// at least 2048 bits), encrypting via the age <c>ssh-rsa</c> recipient type (RSA-OAEP).
/// </summary>
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

    /// <summary>Parses an <c>ssh-rsa AAAA…</c> public key line.</summary>
    /// <exception cref="AgeFormatException">The line is not a valid ssh-rsa public key.</exception>
    public static SshRsaRecipient Parse(string authorizedKeysLine)
    {
        var (keyType, wireBytes, pubKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        if (keyType != "ssh-rsa")
            throw new AgeFormatException($"expected ssh-rsa, got {keyType}");

        if (pubKey is not RsaKeyParameters rsa)
            throw new AgeFormatException("declared ssh-rsa but the key data is a different type");

        if (rsa.Modulus.BitLength < MinKeyBits)
            throw new AgeFormatException($"RSA key must be at least {MinKeyBits} bits, got {rsa.Modulus.BitLength}");

        return new SshRsaRecipient(rsa, wireBytes);
    }

    /// <summary>
    /// Tries to parse an <c>ssh-rsa AAAA…</c> public key line. Returns false
    /// instead of throwing when the input is null, malformed, or a weak key.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? authorizedKeysLine, [MaybeNullWhen(false)] out SshRsaRecipient result)
    {
        if (authorizedKeysLine is not null)
        {
            try
            {
                result = Parse(authorizedKeysLine);
                return true;
            }
            catch (AgeFormatException)
            {
            }
        }

        result = null;
        return false;
    }

    /// <summary>Wraps the file key for this SSH key using RSA-OAEP (SHA-256).</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var oaep = new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest(), new Sha256Digest(), Encoding.ASCII.GetBytes(AgeProtocol.SshRsaOaepLabel));

        oaep.Init(true, _publicKey);
        var input = fileKey.ToArray();
        var body = oaep.ProcessBlock(input, 0, input.Length);

        return new Stanza(AgeProtocol.SshRsaStanzaType, [_tag], body);
    }
}