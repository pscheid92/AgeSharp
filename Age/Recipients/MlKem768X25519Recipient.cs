using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;

namespace Age.Recipients;

/// <summary>
/// A post-quantum ML-KEM-768-X25519 hybrid recipient (<c>age1pq1…</c>), used to
/// encrypt. Instances are immutable and safe to share.
/// </summary>
public sealed class MlKem768X25519Recipient : IRecipient
{
    private const string Hrp = "age1pq";

    private readonly byte[] _publicKey; // 1216 bytes

    internal MlKem768X25519Recipient(byte[] publicKey)
    {
        if (publicKey.Length != XWing.PublicKeySize)
            throw new ArgumentException($"public key must be {XWing.PublicKeySize} bytes, got {publicKey.Length}");

        _publicKey = publicKey;
    }

    /// <summary>
    /// The <c>postquantum</c> security label: prevents mixing this recipient with
    /// classical recipients, which would silently void the post-quantum guarantee.
    /// </summary>
    public string Label =>
        "postquantum";

    /// <summary>Parses a bech32-encoded recipient (<c>age1pq1…</c>, lowercase).</summary>
    /// <exception cref="FormatException">The string is not a valid ML-KEM-768-X25519 recipient.</exception>
    public static MlKem768X25519Recipient Parse(string s)
    {
        var (hrp, data) = Bech32.Decode(s);

        if (hrp != Hrp)
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");

        if (data.Length != XWing.PublicKeySize)
            throw new FormatException($"ML-KEM-768-X25519 public key must be {XWing.PublicKeySize} bytes, got {data.Length}");

        // Must be lowercase
        return s == s.ToLowerInvariant()
            ? new MlKem768X25519Recipient(data)
            : throw new FormatException("age recipient must be lowercase");
    }

    /// <summary>Returns the bech32-encoded recipient string (<c>age1pq1…</c>).</summary>
    public override string ToString() =>
        Bech32.Encode(Hrp, _publicKey);

    /// <summary>Wraps the file key for this recipient via X-Wing HPKE (ML-KEM-768 + X25519).</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Named rather than inlined: passing fileKey.ToArray() as an argument left an uncleared
        // heap copy of the file key itself with no reference to clear it by.
        var fileKeyCopy = fileKey.ToArray();

        try
        {
            var (enc, ct) = HpkeHelper.SealBase(_publicKey, AgeProtocol.MlKemHpkeInfo, fileKeyCopy);
            return new Stanza(AgeProtocol.MlKemStanzaType, [Base64Unpadded.Encode(enc)], ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKeyCopy);
        }
    }
}