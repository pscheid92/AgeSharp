using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     A post-quantum ML-KEM-768-X25519 hybrid identity (<c>AGE-SECRET-KEY-PQ-1…</c>),
///     stored as its 32-byte generation seed. Disposing zeroes the seed; instances
///     are safe for concurrent <see cref="TryUnwrap" /> calls.
/// </summary>
public sealed class MlKem768X25519Identity : IIdentityWithRecipient, IDisposable, IParsable<MlKem768X25519Identity>
{
    private const string Hrp = "AGE-SECRET-KEY-PQ-";
    private const int SeedSize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _seed; // 32 bytes
    private bool _disposed;
    private MlKem768X25519Recipient? _recipient;

    private MlKem768X25519Identity(byte[] seed)
    {
        _seed = seed;
    }

    /// <summary>The matching public recipient (<c>age1pq1…</c>), derived from the seed.</summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public MlKem768X25519Recipient Recipient
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _recipient ??= new MlKem768X25519Recipient(XWing.GeneratePublicKey(_seed));
        }
    }

    IRecipient IIdentityWithRecipient.Recipient => Recipient;

    /// <summary>Returns null for stanzas of another type, or wrapped for a different key.</summary>
    /// <exception cref="AgeFormatException">The stanza claims to be mlkem768x25519 but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.MlKemStanzaType)
            return false;

        if (stanza.Args.Count != 1)
            throw new AgeFormatException(
                $"mlkem768x25519 stanza must have exactly 1 argument, got {stanza.Args.Count}");

        var enc = ParseHelpers.DecodeArg(stanza.Args[0], XWing.EncSize, "mlkem768x25519 enc");

        return stanza.Body.Length == WrappedKeySize
            ? HpkeHelper.OpenBase(enc, _seed, AgeProtocol.MlKemHpkeInfo, stanza.Body.Span, fileKey)
            : throw new AgeFormatException(
                $"mlkem768x25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");
    }

    /// <summary>Zeroes the secret seed.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_seed);
    }

    static MlKem768X25519Identity IParsable<MlKem768X25519Identity>.Parse(string s, IFormatProvider? provider)
    {
        return Parse(s);
    }

    static bool IParsable<MlKem768X25519Identity>.TryParse(string? s, IFormatProvider? provider,
        [MaybeNullWhen(false)] out MlKem768X25519Identity result)
    {
        return TryParse(s, out result);
    }

    /// <summary>Generates a new identity from a cryptographically secure random seed.</summary>
    public static MlKem768X25519Identity Generate()
    {
        var seed = new byte[SeedSize];
        RandomNumberGenerator.Fill(seed);
        return new MlKem768X25519Identity(seed);
    }

    /// <summary>Parses a bech32-encoded secret seed (<c>AGE-SECRET-KEY-PQ-1…</c>, uppercase).</summary>
    /// <exception cref="AgeFormatException">The string is not a valid ML-KEM-768-X25519 secret key.</exception>
    public static MlKem768X25519Identity Parse(string s)
    {
        return new MlKem768X25519Identity(ParseHelpers.DecodeSecretKey(s, Hrp, SeedSize, "ML-KEM-768-X25519 seed"));
    }

    /// <summary>Returns false instead of throwing when the input is null or malformed.</summary>
    public static bool TryParse([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out MlKem768X25519Identity result)
    {
        return ParseHelpers.TryParse(s, Parse, out result);
    }

    /// <summary>Exports the secret key. Handle the result as a secret.</summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public string ToSecretString()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var seedCopy = new byte[SeedSize];
        Array.Copy(_seed, seedCopy, SeedSize);

        var result = Bech32.Encode(Hrp, seedCopy).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(seedCopy);
        return result;
    }

    /// <summary>Redacted: shows only the public half, so logging cannot leak the secret. Never throws.</summary>
    public override string ToString()
    {
        return _disposed
            ? "MlKem768X25519Identity(disposed)"
            : $"MlKem768X25519Identity({Recipient.ToString()[..24]}…)";
    }
}