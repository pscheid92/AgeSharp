using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Recipients;

/// <summary>
/// A native age X25519 identity — the secret half of an age key pair
/// (<c>AGE-SECRET-KEY-1…</c>). Disposing zeroes the key material; instances are
/// safe for concurrent <see cref="Unwrap"/> calls.
/// </summary>
public sealed class X25519Identity : IIdentity, IDisposable
{
    private const string Hrp = "AGE-SECRET-KEY-";
    private const int KeySize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _rawPrivateKey;
    private bool _disposed;

    private X25519Identity(byte[] rawPrivateKey)
    {
        _rawPrivateKey = rawPrivateKey;
    }

    /// <summary>The matching public recipient (<c>age1…</c>), derived from the secret key.</summary>
    public X25519Recipient Recipient => new(PublicKeyParams);

    private X25519PublicKeyParameters PublicKeyParams
    {
        get
        {
            var privateParams = new X25519PrivateKeyParameters(_rawPrivateKey);
            return privateParams.GeneratePublicKey();
        }
    }

    /// <summary>Generates a new identity from a cryptographically secure random key.</summary>
    public static X25519Identity Generate()
    {
        var privateKeyParams = new X25519PrivateKeyParameters(new SecureRandom());
        var raw = new byte[KeySize];
        Array.Copy(privateKeyParams.GetEncoded(), raw, KeySize);
        return new X25519Identity(raw);
    }

    /// <summary>Parses a bech32-encoded secret key (<c>AGE-SECRET-KEY-1…</c>, uppercase).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 secret key.</exception>
    public static X25519Identity Parse(string s)
    {
        // Must be uppercase
        if (s != s.ToUpperInvariant())
            throw new FormatException("age secret key must be uppercase");

        var (hrp, data) = Bech32.Decode(s);

        if (!string.Equals(hrp, Hrp, StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");

        if (data.Length != KeySize)
            throw new FormatException($"X25519 secret key must be {KeySize} bytes, got {data.Length}");

        var raw = new byte[KeySize];
        Array.Copy(data, raw, KeySize);
        CryptographicOperations.ZeroMemory(data);
        return new X25519Identity(raw);
    }

    /// <summary>
    /// Returns the bech32-encoded secret key (<c>AGE-SECRET-KEY-1…</c>), e.g. for
    /// writing to an identity file. Handle the result as a secret.
    /// </summary>
    public string ToSecretString()
    {
        var rawCopy = new byte[KeySize];
        Array.Copy(_rawPrivateKey, rawCopy, KeySize);

        var result = Bech32.Encode(Hrp, rawCopy).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(rawCopy);

        return result;
    }

    /// <summary>
    /// Returns a redacted representation containing only the public recipient, so
    /// accidental logging or string interpolation cannot leak the secret key.
    /// Use <see cref="ToSecretString"/> to export the secret key.
    /// </summary>
    public override string ToString() =>
        $"X25519Identity({Recipient})";

    /// <summary>
    /// Attempts to unwrap the file key from an X25519 stanza. Returns null for
    /// stanzas of other types or wrapped for a different recipient.
    /// </summary>
    /// <exception cref="AgeHeaderException">The stanza claims to be X25519 but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.X25519StanzaType) return null;

        if (stanza.Args.Count != 1)
            throw new AgeHeaderException($"X25519 stanza must have exactly 1 argument, got {stanza.Args.Count}");

        byte[] ephPubBytes;
        try
        {
            ephPubBytes = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"invalid X25519 ephemeral key encoding: {ex.Message}", ex);
        }

        if (ephPubBytes.Length != KeySize)
            throw new AgeHeaderException($"X25519 ephemeral key must be {KeySize} bytes, got {ephPubBytes.Length}");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeHeaderException($"X25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privateKeyParams = new X25519PrivateKeyParameters(_rawPrivateKey);

        // DH: identity × ephemeral
        var agreement = new X25519Agreement();
        agreement.Init(privateKeyParams);
        var sharedSecret = new byte[agreement.AgreementSize];
        try
        {
            agreement.CalculateAgreement(ephPub, sharedSecret, 0);
        }
        catch (InvalidOperationException)
        {
            throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)");
        }

        // BouncyCastle may not reject all low-order points — check for all-zero shared secret
        if (sharedSecret.All(b => b == 0))
            throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)");

        // HKDF: salt = ephPub || recipientPub, info = label
        var recipientPubBytes = PublicKeyParams.GetEncoded();
        var salt = (byte[])[.. ephPubBytes, .. recipientPubBytes];

        var wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.X25519HkdfLabel, KeySize);

        try
        {
            // Decrypt file key
            var zeroNonce = new byte[12];

            // AEAD failure → wrong recipient, not our stanza
            return CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>Zeroes the secret key material.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_rawPrivateKey);
    }
}