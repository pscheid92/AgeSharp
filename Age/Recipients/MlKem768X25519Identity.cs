using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;

namespace Age.Recipients;

/// <summary>
/// A post-quantum ML-KEM-768-X25519 hybrid identity (<c>AGE-SECRET-KEY-PQ-1…</c>),
/// stored as its 32-byte generation seed. Disposing zeroes the seed; instances
/// are safe for concurrent <see cref="Unwrap"/> calls.
/// </summary>
public sealed class MlKem768X25519Identity : IIdentity, IDisposable
{
    private const string Hrp = "AGE-SECRET-KEY-PQ-";
    private const int SeedSize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _seed; // 32 bytes
    private bool _disposed;

    private MlKem768X25519Identity(byte[] seed)
    {
        _seed = seed;
    }

    /// <summary>The matching public recipient (<c>age1pq1…</c>), derived from the seed.</summary>
    public MlKem768X25519Recipient Recipient =>
        new(XWing.GeneratePublicKey(_seed));

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
        // Must be uppercase
        if (s != s.ToUpperInvariant())
            throw new AgeFormatException("age secret key must be uppercase");

        var (hrp, data) = Bech32.Decode(s);

        if (!string.Equals(hrp, Hrp, StringComparison.OrdinalIgnoreCase))
            throw new AgeFormatException($"expected HRP '{Hrp}', got '{hrp}'");

        if (data.Length != SeedSize)
            throw new AgeFormatException($"ML-KEM-768-X25519 seed must be {SeedSize} bytes, got {data.Length}");

        var seed = new byte[SeedSize];
        Array.Copy(data, seed, SeedSize);
        CryptographicOperations.ZeroMemory(data);
        return new MlKem768X25519Identity(seed);
    }

    /// <summary>
    /// Returns the bech32-encoded secret seed (<c>AGE-SECRET-KEY-PQ-1…</c>), e.g. for
    /// writing to an identity file. Handle the result as a secret.
    /// </summary>
    public string ToSecretString()
    {
        var seedCopy = new byte[SeedSize];
        Array.Copy(_seed, seedCopy, SeedSize);

        var result = Bech32.Encode(Hrp, seedCopy).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(seedCopy);
        return result;
    }

    /// <summary>
    /// Returns a redacted representation containing only a prefix of the public
    /// recipient (the full recipient is ~2000 characters), so accidental logging
    /// or string interpolation cannot leak the secret seed. Use
    /// <see cref="ToSecretString"/> to export the secret.
    /// </summary>
    public override string ToString() =>
        $"MlKem768X25519Identity({Recipient.ToString()[..24]}…)";

    /// <summary>
    /// Attempts to unwrap the file key from an <c>mlkem768x25519</c> stanza.
    /// Returns null for stanzas of other types or wrapped for a different recipient.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza claims to be mlkem768x25519 but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.MlKemStanzaType)
            return null;

        if (stanza.Args.Count != 1)
            throw new AgeFormatException($"mlkem768x25519 stanza must have exactly 1 argument, got {stanza.Args.Count}");

        byte[] enc;
        try
        {
            enc = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"invalid mlkem768x25519 enc encoding: {ex.Message}", ex);
        }

        if (enc.Length != XWing.EncSize)
            throw new AgeFormatException($"mlkem768x25519 enc must be {XWing.EncSize} bytes, got {enc.Length}");

        return stanza.Body.Length == WrappedKeySize
            ? HpkeHelper.OpenBase(enc, _seed, AgeProtocol.MlKemHpkeInfo, stanza.Body.ToArray())
            : throw new AgeFormatException($"mlkem768x25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");
    }

    /// <summary>Zeroes the secret seed.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_seed);
    }
}