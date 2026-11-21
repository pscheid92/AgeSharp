using System.Security.Cryptography;
using AgeSharp.Crypto;
using AgeSharp;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
/// A native age X25519 identity — the secret half of an age key pair
/// (<c>AGE-SECRET-KEY-1…</c>). Disposing zeroes the key material; instances are
/// safe for concurrent <see cref="TryUnwrap"/> calls.
/// </summary>
public sealed class X25519Identity : IIdentityWithRecipient, IDisposable
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
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public X25519Recipient Recipient
    {
        get
        {
            // Without this guard a disposed identity derives from the all-zero key
            // and returns a well-formed, publicly derivable recipient.
            ObjectDisposedException.ThrowIf(_disposed, this);
            return new(PublicKeyParams);
        }
    }

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
        // Encoded straight into the array this identity owns and clears: GetEncoded would hand
        // back one more copy of the key, which nothing clears.
        var raw = new byte[KeySize];
        new X25519PrivateKeyParameters(new SecureRandom()).Encode(raw, 0);
        return new X25519Identity(raw);
    }

    /// <summary>Parses a bech32-encoded secret key (<c>AGE-SECRET-KEY-1…</c>, uppercase).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 secret key.</exception>
    public static X25519Identity Parse(string s)
    {
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
    /// Use <see cref="ToSecretString"/> to export the secret key.
    /// Never throws: a disposed identity renders as <c>X25519Identity(disposed)</c>,
    /// so debugger and logging calls stay safe.
    /// </summary>
    public override string ToString() =>
        _disposed ? "X25519Identity(disposed)" : $"X25519Identity({Recipient})";

    IRecipient IIdentityWithRecipient.Recipient =>
        Recipient;

    /// <summary>
    /// Unwraps the file key from an X25519 stanza into <paramref name="fileKey"/>: false for
    /// stanzas of other types or wrapped for a different recipient.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza claims to be X25519 but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) =>
        UnwrapInto(stanza, fileKey);

    // The file key is never in an array of ours: it is decrypted on the stack.
    private bool UnwrapInto(Stanza stanza, Span<byte> fileKey)
    {
        FileKey.RequireBuffer(fileKey);

        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.X25519StanzaType) return false;

        if (stanza.Args.Count != 1)
            throw new AgeFormatException($"X25519 stanza must have exactly 1 argument, got {stanza.Args.Count}");

        byte[] ephPubBytes;
        try
        {
            ephPubBytes = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (FormatException ex)
        {
            throw new AgeFormatException($"invalid X25519 ephemeral key encoding: {ex.Message}", ex);
        }

        if (ephPubBytes.Length != KeySize)
            throw new AgeFormatException($"X25519 ephemeral key must be {KeySize} bytes, got {ephPubBytes.Length}");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeFormatException($"X25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privateKeyParams = new X25519PrivateKeyParameters(_rawPrivateKey);

        // The try opens before the agreement, not after the derivation, so the shared secret is
        // covered from allocation rather than from first use.
        var sharedSecret = new byte[CryptoHelper.X25519SharedSecretSize];
        byte[]? wrapKey = null;

        try
        {
            CryptoHelper.X25519Agree(privateKeyParams, ephPub, sharedSecret);

            // HKDF: salt = ephPub || recipientPub, info = label
            var recipientPubBytes = PublicKeyParams.GetEncoded();
            var salt = (byte[])[.. ephPubBytes, .. recipientPubBytes];

            wrapKey = CryptoHelper.HkdfDerive(sharedSecret, salt, AgeProtocol.X25519HkdfLabel, KeySize);

            // Decrypt file key. An AEAD failure means a wrong recipient, not our stanza.
            var zeroNonce = new byte[12];

            // On the stack, not in an array: the key reaches the caller's buffer only if it
            // authenticates, so an identity that declines leaves the buffer as it was.
            Span<byte> candidate = stackalloc byte[FileKey.Size];

            try
            {
                if (!CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body.Span, candidate))
                    return false;

                candidate.CopyTo(fileKey);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(candidate);
            }
        }
        finally
        {
            if (wrapKey is not null)
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