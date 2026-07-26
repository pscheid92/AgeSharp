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

    /// <summary>
    ///     The <c>authorized_keys</c> line for this key — the same form
    ///     <see cref="Parse" /> accepts, so a parsed recipient round-trips.
    /// </summary>
    public override string ToString()
    {
        return $"ssh-ed25519 {Convert.ToBase64String(_sshWireBytes)}";
    }

    /// <summary>Wraps the file key for this SSH key via tweaked X25519 + ChaCha20-Poly1305.</summary>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        Span<byte> tweak = stackalloc byte[KeySize];
        Span<byte> tweakedKey = stackalloc byte[CryptoHelper.X25519SharedSecretSize];
        Span<byte> sharedSecret = stackalloc byte[CryptoHelper.X25519SharedSecretSize];
        Span<byte> wrapKey = stackalloc byte[KeySize];

        try
        {
            CryptoHelper.HkdfDerive([], _sshWireBytes, AgeProtocol.SshEd25519HkdfLabel, tweak);

            var tweakPrivate = new X25519PrivateKeyParameters(tweak);
            var recipientPub = new X25519PublicKeyParameters(_x25519PublicKey);
            CryptoHelper.X25519Agree(tweakPrivate, recipientPub, tweakedKey);

            var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
            var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

            // tweakedKey is a point, so it serves as the public key for the second agreement.
            var tweakedPub = new X25519PublicKeyParameters(tweakedKey);
            CryptoHelper.X25519Agree(ephemeral, tweakedPub, sharedSecret);

            var salt = (byte[])[.. ephPubBytes, .. _x25519PublicKey];
            CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.SshEd25519HkdfLabel, wrapKey);

            Span<byte> zeroNonce = stackalloc byte[NonceSize];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return [new Stanza(AgeProtocol.SshEd25519StanzaType, [_tag, ephPubB64], body)];
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

    /// <summary>Returns false instead of throwing when the input is null or malformed.</summary>
    public static bool TryParse([NotNullWhen(true)] string? authorizedKeysLine,
        [MaybeNullWhen(false)] out SshEd25519Recipient result)
    {
        return ParseHelpers.TryParse(authorizedKeysLine, Parse, out result);
    }
}