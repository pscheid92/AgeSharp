using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

/// <summary>
/// A native age X25519 recipient — the public half of an age key pair
/// (<c>age1…</c>), used to encrypt. Instances are immutable and safe to share.
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

    /// <summary>Parses a bech32-encoded recipient (<c>age1…</c>, lowercase).</summary>
    /// <exception cref="AgeFormatException">The string is not a valid X25519 recipient.</exception>
    public static X25519Recipient Parse(string s)
    {
        var (hrp, data) = Bech32.Decode(s);
        
        if (hrp != Hrp)
            throw new AgeFormatException($"expected HRP '{Hrp}', got '{hrp}'");
        
        if (data.Length != KeySize)
            throw new AgeFormatException($"X25519 public key must be {KeySize} bytes, got {data.Length}");

        // Must be lowercase
        if (s != s.ToLowerInvariant())
            throw new AgeFormatException("age recipient must be lowercase");

        return new X25519Recipient(new X25519PublicKeyParameters(data));
    }

    /// <summary>
    /// Tries to parse a bech32-encoded recipient (<c>age1…</c>). Returns false
    /// instead of throwing when the input is null or malformed.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out X25519Recipient result) =>
        ParseHelpers.TryParse(s, Parse, out result);

    static X25519Recipient IParsable<X25519Recipient>.Parse(string s, IFormatProvider? provider) =>
        Parse(s);

    static bool IParsable<X25519Recipient>.TryParse(string? s, IFormatProvider? provider, [MaybeNullWhen(false)] out X25519Recipient result) =>
        TryParse(s, out result);

    /// <summary>Returns the bech32-encoded recipient string (<c>age1…</c>).</summary>
    public override string ToString() =>
        Bech32.Encode(Hrp, _publicKey.GetEncoded());

    /// <summary>Wraps the file key for this recipient using ephemeral X25519 + ChaCha20-Poly1305.</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Generate ephemeral X25519 key pair
        var ephemeral = new X25519PrivateKeyParameters(new SecureRandom());
        var ephPubBytes = ephemeral.GeneratePublicKey().GetEncoded();

        // DH: ephemeral × recipient
        var agreement = new X25519Agreement();
        agreement.Init(ephemeral);
        var sharedSecret = new byte[agreement.AgreementSize];

        try
        {
            agreement.CalculateAgreement(_publicKey, sharedSecret, 0);
        }
        catch (InvalidOperationException)
        {
            throw new AgeException("X25519 key agreement failed (shared secret is zero)");
        }

        // BouncyCastle may not reject all low-order points — check for all-zero shared secret
        if (sharedSecret.All(b => b == 0))
            throw new AgeException("X25519 key agreement failed (shared secret is zero)");

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
}