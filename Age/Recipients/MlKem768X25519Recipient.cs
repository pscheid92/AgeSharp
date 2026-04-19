using Age.Crypto;
using Age.Format;

namespace Age.Recipients;

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

    public string Label =>
        "postquantum";

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

    public override string ToString() =>
        Bech32.Encode(Hrp, _publicKey);

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var (enc, ct) = HpkeHelper.SealBase(_publicKey, AgeProtocol.MlKemHpkeInfo, fileKey.ToArray());
        var encB64 = Base64Unpadded.Encode(enc);
        return new Stanza(AgeProtocol.MlKemStanzaType, [encB64], ct);
    }
}