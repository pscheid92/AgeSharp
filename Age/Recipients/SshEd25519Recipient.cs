using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
///     A recipient backed by an ssh-ed25519 public key (an <c>authorized_keys</c>
///     line), encrypting via the age <c>ssh-ed25519</c> recipient type.
/// </summary>
public sealed class SshEd25519Recipient : IRecipient
{
    private const int KeySize = 32;
    private const int NonceSize = 12;

    private readonly byte[] _sshWireBytes;
    private readonly string _tag;
    private readonly byte[] _x25519PublicKey;

    internal SshEd25519Recipient(byte[] sshWireBytes, byte[] x25519PublicKey)
    {
        _sshWireBytes = sshWireBytes;
        _x25519PublicKey = x25519PublicKey;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    /// <summary>Wraps the file key for this SSH key via tweaked X25519 + ChaCha20-Poly1305.</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Compute tweak = HKDF(ikm=[], salt=sshWireBytes, info=label, 32)
        var tweak = CryptoHelper.HkdfDerive([], _sshWireBytes, AgeProtocol.SshEd25519HkdfLabel, KeySize);

        // tweakedKey = X25519.ScalarMult(tweak, _x25519PublicKey)
        var tweakPrivate = new X25519PrivateKeyParameters(tweak);
        var recipientPub = new X25519PublicKeyParameters(_x25519PublicKey);
        var tweakedKey = CryptoHelper.X25519Agree(tweakPrivate, recipientPub);

        // Generate ephemeral X25519 key pair
        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // sharedSecret = X25519.ScalarMult(ephSecret, tweakedKey)
        // tweakedKey is a point; use it as a public key for the agreement.
        var tweakedPub = new X25519PublicKeyParameters(tweakedKey);
        var sharedSecret = CryptoHelper.X25519Agree(ephemeral, tweakedPub);

        // wrapKey = HKDF(ikm=sharedSecret, salt=ephPub||convertedKey, info=label, 32)
        var salt = (byte[])[.. ephPubBytes, .. _x25519PublicKey];
        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.SshEd25519HkdfLabel, KeySize);

        try
        {
            var zeroNonce = new byte[NonceSize];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(AgeProtocol.SshEd25519StanzaType, [_tag, ephPubB64], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(tweakedKey);
            CryptographicOperations.ZeroMemory(tweak);
        }
    }

    /// <summary>Parses an <c>ssh-ed25519 AAAA…</c> public key line.</summary>
    /// <exception cref="AgeFormatException">The line is not a valid ssh-ed25519 public key.</exception>
    public static SshEd25519Recipient Parse(string authorizedKeysLine)
    {
        var (keyType, wireBytes, pubKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        if (keyType != "ssh-ed25519")
            throw new AgeFormatException($"expected ssh-ed25519, got {keyType}");

        if (pubKey is not Ed25519PublicKeyParameters ed25519Pub)
            throw new AgeFormatException("declared ssh-ed25519 but the key data is a different type");

        var x25519Pub = Ed25519Converter.PublicKeyToX25519(ed25519Pub.GetEncoded());
        return new SshEd25519Recipient(wireBytes, x25519Pub);
    }

    /// <summary>
    ///     Tries to parse an <c>ssh-ed25519 AAAA…</c> public key line. Returns false
    ///     instead of throwing when the input is null or malformed.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? authorizedKeysLine,
        [MaybeNullWhen(false)] out SshEd25519Recipient result)
    {
        return ParseHelpers.TryParse(authorizedKeysLine, Parse, out result);
    }
}