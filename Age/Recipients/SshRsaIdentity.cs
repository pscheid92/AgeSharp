using System.Text;
using AgeSharp.Crypto;
using AgeSharp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace AgeSharp;

/// <summary>
/// An identity backed by an ssh-rsa private key, decrypting the age
/// <c>ssh-rsa</c> recipient type (RSA-OAEP).
/// </summary>
public sealed class SshRsaIdentity : IIdentityWithRecipient, IDisposable
{
    private readonly RsaPrivateCrtKeyParameters _privateKey;
    private readonly byte[] _sshWireBytes;
    private readonly string _tag;
    private bool _disposed;

    private SshRsaIdentity(RsaPrivateCrtKeyParameters privateKey, byte[] sshWireBytes)
    {
        _privateKey = privateKey;
        _sshWireBytes = sshWireBytes;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    /// <summary>The matching recipient, derived from the RSA public parameters.</summary>
    public SshRsaRecipient Recipient =>
        new(new RsaKeyParameters(false, _privateKey.Modulus, _privateKey.PublicExponent), _sshWireBytes);

    /// <summary>Parses an ssh-rsa private key from PEM text (OpenSSH, PKCS#1, or PKCS#8).</summary>
    /// <exception cref="FormatException">The text is not a valid ssh-rsa private key.</exception>
    public static SshRsaIdentity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privateKey) = SshKeyParser.ParsePrivateKey(pemText);
        return FromParsedKey(keyType, publicWireBytes, privateKey);
    }

    internal static SshRsaIdentity FromParsedKey(string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey)
    {
        return keyType == "ssh-rsa"
            ? new SshRsaIdentity((RsaPrivateCrtKeyParameters)privateKey, publicWireBytes)
            : throw new FormatException($"expected ssh-rsa private key, got {keyType}");
    }

    IRecipient IIdentityWithRecipient.Recipient =>
        Recipient;

    /// <summary>
    /// Attempts to unwrap the file key from an <c>ssh-rsa</c> stanza. Returns null
    /// for stanzas of other types or addressed to a different SSH key (tag mismatch).
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza claims to be ssh-rsa but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) =>
        FileKey.Deliver(UnwrapToArray(stanza), fileKey);

    private byte[]? UnwrapToArray(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.SshRsaStanzaType)
            return null;

        if (stanza.Args.Count != 1)
            throw new AgeFormatException($"ssh-rsa stanza must have exactly 1 argument, got {stanza.Args.Count}");

        if (stanza.Args[0] != _tag)
            return null;

        var oaep = new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest(), new Sha256Digest(), Encoding.ASCII.GetBytes(AgeProtocol.SshRsaOaepLabel));
        oaep.Init(false, _privateKey);

        try
        {
            return oaep.ProcessBlock(stanza.Body.ToArray(), 0, stanza.Body.Length);
        }
        catch (InvalidCipherTextException)
        {
            return null;
        }
        catch (DataLengthException)
        {
            return null;
        }
    }

    /// <summary>
    /// Marks the identity disposed. RSA BigInteger fields cannot be reliably
    /// zeroed in BouncyCastle, so unlike the other identity types no key
    /// material is wiped.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
    }
}