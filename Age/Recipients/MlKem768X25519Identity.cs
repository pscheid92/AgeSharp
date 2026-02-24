using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Format;

namespace Age.Recipients;

public sealed class MlKem768X25519Identity : IIdentity, IDisposable
{
    private const string StanzaType = "mlkem768x25519";
    private const string Hrp = "AGE-SECRET-KEY-PQ-";

    private static readonly byte[] HpkeInfo = Encoding.ASCII.GetBytes("age-encryption.org/mlkem768x25519");

    private readonly byte[] _seed;  // 32 bytes
    private bool _disposed;

    private MlKem768X25519Identity(byte[] seed)
    {
        _seed = seed;
    }

    public MlKem768X25519Recipient Recipient => new(XWing.GeneratePublicKey(_seed));

    public static MlKem768X25519Identity Generate()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        return new MlKem768X25519Identity(seed);
    }

    public static MlKem768X25519Identity Parse(string s)
    {
        // Must be uppercase
        if (s != s.ToUpperInvariant())
            throw new FormatException("age secret key must be uppercase");

        var (hrp, data) = Bech32.Decode(s);
        if (!string.Equals(hrp, Hrp, StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");
        if (data.Length != 32)
            throw new FormatException($"ML-KEM-768-X25519 seed must be 32 bytes, got {data.Length}");

        var seed = new byte[32];
        Array.Copy(data, seed, 32);
        CryptographicOperations.ZeroMemory(data);
        return new MlKem768X25519Identity(seed);
    }

    public override string ToString()
    {
        var seedCopy = new byte[32];
        Array.Copy(_seed, seedCopy, 32);
        var result = Bech32.Encode(Hrp, seedCopy).ToUpperInvariant();
        CryptographicOperations.ZeroMemory(seedCopy);
        return result;
    }

    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != StanzaType) return null;

        if (stanza.Args.Length != 1)
            throw new AgeHeaderException($"mlkem768x25519 stanza must have exactly 1 argument, got {stanza.Args.Length}");

        byte[] enc;
        try
        {
            enc = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"invalid mlkem768x25519 enc encoding: {ex.Message}", ex);
        }

        if (enc.Length != XWing.EncSize)
            throw new AgeHeaderException($"mlkem768x25519 enc must be {XWing.EncSize} bytes, got {enc.Length}");

        if (stanza.Body.Length != 32) // 16 bytes file key + 16 bytes Poly1305 tag
            throw new AgeHeaderException($"mlkem768x25519 stanza body must be 32 bytes, got {stanza.Body.Length}");

        return HpkeHelper.OpenBase(enc, _seed, HpkeInfo, stanza.Body);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_seed);
    }
}
