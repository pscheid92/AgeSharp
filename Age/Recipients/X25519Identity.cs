using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
/// A native age X25519 identity — the secret half of an age key pair
/// (<c>AGE-SECRET-KEY-1…</c>). Disposing zeroes the key material; instances are
/// safe for concurrent <see cref="Unwrap"/> calls.
/// </summary>
public sealed class X25519Identity : IIdentityWithRecipient, IDisposable, IParsable<X25519Identity>
{
    private const string Hrp = "AGE-SECRET-KEY-";
    private const int KeySize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _rawPrivateKey;
    private X25519PublicKeyParameters? _publicKeyParams;
    private X25519Recipient? _recipient;
    private bool _disposed;

    private X25519Identity(byte[] rawPrivateKey)
    {
        _rawPrivateKey = rawPrivateKey;
    }

    /// <summary>The matching public recipient (<c>age1…</c>), derived from the secret key.</summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public X25519Recipient Recipient
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _recipient ??= new(PublicKeyParams);
        }
    }

    // Bridges the strongly-typed property above to IIdentityWithRecipient. C# has no
    // covariant returns for interface implementations, so the interface member is
    // implemented explicitly rather than widening the public property to IRecipient.
    IRecipient IIdentityWithRecipient.Recipient => Recipient;

    // Deriving the public half is a scalar multiplication, and Unwrap needs it once
    // per stanza to build the HKDF salt — so an N-stanza header used to cost N of
    // them on top of the N agreements. Cached on first use instead.
    //
    // No lock: the derivation is deterministic, so two racing threads compute the
    // same value and either may win. Reference assignment is atomic, which keeps
    // the documented "safe for concurrent Unwrap" contract intact. Lazy rather than
    // eager because parsing an identity file should not pay for keys never used.
    private X25519PublicKeyParameters PublicKeyParams =>
        _publicKeyParams ??= new X25519PrivateKeyParameters(_rawPrivateKey).GeneratePublicKey();

    /// <summary>Generates a new identity from a cryptographically secure random key.</summary>
    public static X25519Identity Generate()
    {
        var privateKeyParams = new X25519PrivateKeyParameters(new SecureRandom());
        var raw = new byte[KeySize];
        Array.Copy(privateKeyParams.GetEncoded(), raw, KeySize);
        return new X25519Identity(raw);
    }

    /// <summary>Parses a bech32-encoded secret key (<c>AGE-SECRET-KEY-1…</c>, uppercase).</summary>
    /// <exception cref="AgeFormatException">The string is not a valid X25519 secret key.</exception>
    public static X25519Identity Parse(string s) =>
        new(ParseHelpers.DecodeSecretKey(s, Hrp, KeySize, "X25519 secret key"));

    /// <summary>
    /// Tries to parse a bech32-encoded secret key (<c>AGE-SECRET-KEY-1…</c>).
    /// Returns false instead of throwing when the input is null or malformed.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out X25519Identity result) =>
        ParseHelpers.TryParse(s, Parse, out result);

    static X25519Identity IParsable<X25519Identity>.Parse(string s, IFormatProvider? provider) =>
        Parse(s);

    static bool IParsable<X25519Identity>.TryParse(string? s, IFormatProvider? provider, [MaybeNullWhen(false)] out X25519Identity result) =>
        TryParse(s, out result);

    /// <summary>
    /// Returns the bech32-encoded secret key (<c>AGE-SECRET-KEY-1…</c>), e.g. for
    /// writing to an identity file. Handle the result as a secret.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public string ToSecretString()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var rawCopy = new byte[KeySize];
        Array.Copy(_rawPrivateKey, rawCopy, KeySize);

        var result = Bech32.Encode(Hrp, rawCopy).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(rawCopy);

        return result;
    }

    /// <summary>
    /// Returns a redacted representation containing only the public recipient, so
    /// accidental logging or string interpolation cannot leak the secret key.
    /// Use <see cref="ToSecretString"/> to export the secret key. Once disposed,
    /// returns <c>X25519Identity(disposed)</c> — unlike the other members this
    /// never throws, because debuggers, loggers, and exception-message formatting
    /// all call <c>ToString</c> and must not fail on a disposed instance.
    /// </summary>
    public override string ToString() =>
        _disposed ? "X25519Identity(disposed)" : $"X25519Identity({Recipient})";

    /// <summary>
    /// Attempts to unwrap the file key from an X25519 stanza. Returns null for
    /// stanzas of other types or wrapped for a different recipient.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza claims to be X25519 but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.X25519StanzaType) return null;

        if (stanza.Args.Count != 1)
            throw new AgeFormatException($"X25519 stanza must have exactly 1 argument, got {stanza.Args.Count}");

        var ephPubBytes = ParseHelpers.DecodeArg(stanza.Args[0], KeySize, "X25519 ephemeral key");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeFormatException($"X25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privateKeyParams = new X25519PrivateKeyParameters(_rawPrivateKey);

        // DH: identity × ephemeral (guards against low-order/all-zero results)
        var sharedSecret = CryptoHelper.X25519Agree(privateKeyParams, ephPub);

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