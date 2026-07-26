using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
///     The secret half of a native age key pair (<c>AGE-SECRET-KEY-1…</c>). Disposing zeroes
///     the key material; instances are safe for concurrent <see cref="Unwrap" /> calls.
/// </summary>
public sealed class X25519Identity : IIdentityWithRecipient, IDisposable, IParsable<X25519Identity>
{
    private const string Hrp = "AGE-SECRET-KEY-";
    private const int KeySize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _rawPrivateKey;
    private bool _disposed;
    private X25519PublicKeyParameters? _publicKeyParams;
    private X25519Recipient? _recipient;

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
            return _recipient ??= new X25519Recipient(PublicKeyParams);
        }
    }

    // Cached: Unwrap needs the public half once per stanza. No lock — the derivation is
// deterministic, so racing threads compute the same value and reference assignment is atomic.
    private X25519PublicKeyParameters PublicKeyParams =>
        _publicKeyParams ??= new X25519PrivateKeyParameters(_rawPrivateKey).GeneratePublicKey();

    IRecipient IIdentityWithRecipient.Recipient => Recipient;

    /// <summary>Returns null for stanzas of another type, or wrapped for a different key.</summary>
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
            throw new AgeFormatException(
                $"X25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privateKeyParams = new X25519PrivateKeyParameters(_rawPrivateKey);

        Span<byte> sharedSecret = stackalloc byte[CryptoHelper.X25519SharedSecretSize];
        Span<byte> wrapKey = stackalloc byte[KeySize];

        try
        {
            CryptoHelper.X25519Agree(privateKeyParams, ephPub, sharedSecret);

            var salt = (byte[])[.. ephPubBytes, .. PublicKeyParams.GetEncoded()];
            CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.X25519HkdfLabel, wrapKey);

            Span<byte> zeroNonce = stackalloc byte[12];
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

    static X25519Identity IParsable<X25519Identity>.Parse(string s, IFormatProvider? provider)
    {
        return Parse(s);
    }

    static bool IParsable<X25519Identity>.TryParse(string? s, IFormatProvider? provider,
        [MaybeNullWhen(false)] out X25519Identity result)
    {
        return TryParse(s, out result);
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
    /// <exception cref="AgeFormatException">The string is not a valid X25519 secret key.</exception>
    public static X25519Identity Parse(string s)
    {
        return new X25519Identity(ParseHelpers.DecodeSecretKey(s, Hrp, KeySize, "X25519 secret key"));
    }

    /// <summary>Returns false instead of throwing when the input is null or malformed.</summary>
    public static bool TryParse([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out X25519Identity result)
    {
        return ParseHelpers.TryParse(s, Parse, out result);
    }

    /// <summary>Exports the secret key. Handle the result as a secret.</summary>
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

    /// <summary>Redacted: shows only the public half, so logging cannot leak the secret. Never throws.</summary>
    public override string ToString()
    {
        return _disposed ? "X25519Identity(disposed)" : $"X25519Identity({Recipient})";
    }
}