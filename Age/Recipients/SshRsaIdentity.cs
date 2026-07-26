using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace AgeSharp;

/// <summary>
///     An identity backed by an ssh-rsa private key, decrypting the age
///     <c>ssh-rsa</c> recipient type (RSA-OAEP).
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
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public SshRsaRecipient Recipient
    {
        get
        {
            // A disposed identity is unusable by contract, even where the public half survives.
            ObjectDisposedException.ThrowIf(_disposed, this);
            return new SshRsaRecipient(new RsaKeyParameters(false, _privateKey.Modulus, _privateKey.PublicExponent),
                _sshWireBytes);
        }
    }

    IRecipient IIdentityWithRecipient.Recipient => Recipient;

    /// <summary>Returns null for stanzas of another type, or wrapped for a different key.</summary>
    /// <exception cref="AgeFormatException">The stanza claims to be ssh-rsa but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != Stanza.SshRsa)
            return false;

        if (stanza.Args.Count != 1)
            throw new AgeFormatException($"ssh-rsa stanza must have exactly 1 argument, got {stanza.Args.Count}");

        if (stanza.Args[0] != _tag)
            return false;

        var oaep = new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest(), new Sha256Digest(),
            Encoding.ASCII.GetBytes(AgeProtocol.SshRsaOaepLabel));
        oaep.Init(false, _privateKey);

        byte[] unwrapped;

        try
        {
            // BouncyCastle's OAEP allocates its own output, so this copies into the caller's
            // buffer and clears the array it handed back.
            unwrapped = oaep.ProcessBlock(stanza.Body.ToArray(), 0, stanza.Body.Length);
        }
        catch (InvalidCipherTextException)
        {
            return false;
        }
        catch (DataLengthException)
        {
            return false;
        }

        try
        {
            if (unwrapped.Length != fileKey.Length)
                return false;

            unwrapped.CopyTo(fileKey);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(unwrapped);
        }
    }

    /// <summary>
    ///     Marks the identity disposed. RSA BigInteger fields cannot be reliably
    ///     zeroed in BouncyCastle, so unlike the other identity types no key
    ///     material is wiped.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
    }

    /// <summary>Parses an ssh-rsa private key from PEM text (OpenSSH, PKCS#1, or PKCS#8).</summary>
    /// <exception cref="AgeFormatException">The text is not a valid ssh-rsa private key.</exception>
    public static SshRsaIdentity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privateKey) = SshKeyParser.ParsePrivateKey(pemText);

        if (keyType != "ssh-rsa")
            throw new AgeFormatException($"expected ssh-rsa private key, got {keyType}");

        if (privateKey is not RsaPrivateCrtKeyParameters rsaPrivate)
            throw new AgeFormatException("declared ssh-rsa but the key data is a different type");

        return new SshRsaIdentity(rsaPrivate, publicWireBytes);
    }

    /// <summary>Returns false instead of throwing when the input is null or malformed.</summary>
    public static bool TryParse([NotNullWhen(true)] string? pemText, [MaybeNullWhen(false)] out SshRsaIdentity result)
    {
        return ParseHelpers.TryParse(pemText, Parse, out result);
    }
}