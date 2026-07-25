using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
///     A native age X25519 recipient — the public half of an age key pair
///     (<c>age1…</c>), used to encrypt. Instances are immutable and safe to share.
/// </summary>
public sealed class X25519Recipient : IRecipient, IParsable<X25519Recipient>
{
    private const string Hrp = "age";
    private const int KeySize = 32;

    private readonly X25519PublicKeyParameters _publicKey;

    internal X25519Recipient(X25519PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
    }

    static X25519Recipient IParsable<X25519Recipient>.Parse(string s, IFormatProvider? provider)
    {
        return Parse(s);
    }

    static bool IParsable<X25519Recipient>.TryParse(string? s, IFormatProvider? provider,
        [MaybeNullWhen(false)] out X25519Recipient result)
    {
        return TryParse(s, out result);
    }

    /// <summary>Wraps the file key for this recipient using ephemeral X25519 + ChaCha20-Poly1305.</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Generate ephemeral X25519 key pair
        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // DH: ephemeral × recipient. A recipient parsed from a hostile age1… string can
        // carry a low-order point, so this rejects an all-zero secret on the encrypt
        // side too — see CryptoHelper.X25519Agree for the rule.
        var sharedSecret = CryptoHelper.X25519Agree(ephemeral, _publicKey);

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = _publicKey.GetEncoded();
        var salt = (byte[])[.. ephPubBytes, .. recipientPubBytes];

        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.X25519HkdfLabel, KeySize);

        try
        {
            // Encrypt file key with ChaCha20-Poly1305, zero nonce
            var zeroNonce = new byte[12];
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);

            var ephPubB64 = Base64Unpadded.Encode(ephPubBytes);
            return new Stanza(AgeProtocol.X25519StanzaType, [ephPubB64], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>Parses a bech32-encoded recipient (<c>age1…</c>, lowercase).</summary>
    /// <exception cref="AgeFormatException">The string is not a valid X25519 recipient.</exception>
    public static X25519Recipient Parse(string s)
    {
        return new X25519Recipient(new X25519PublicKeyParameters(
            ParseHelpers.DecodeRecipientKey(s, Hrp, KeySize, "X25519 public key")));
    }

    /// <summary>
    ///     Tries to parse a bech32-encoded recipient (<c>age1…</c>). Returns false
    ///     instead of throwing when the input is null or malformed.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out X25519Recipient result)
    {
        return ParseHelpers.TryParse(s, Parse, out result);
    }

    /// <summary>Returns the bech32-encoded recipient string (<c>age1…</c>).</summary>
    public override string ToString()
    {
        return Bech32.Encode(Hrp, _publicKey.GetEncoded());
    }
}