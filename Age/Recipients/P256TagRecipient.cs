using AgeSharp.Crypto;
using AgeSharp;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
/// A tagged P-256 recipient (<c>age1tag1…</c>), used to encrypt to a key held on hardware,
/// such as a YubiKey or a Secure Enclave. Instances are immutable and safe to share.
/// </summary>
/// <remarks>
/// Encryption only, as in go-age and rage: decrypting is the job of the plugin that talks to
/// the hardware (through <see cref="PluginIdentity"/>). The file key is sealed with HPKE,
/// DHKEM(P-256, HKDF-SHA256) with ChaCha20-Poly1305, and the stanza carries a tag that lets the
/// hardware recognise it, which makes files encrypted to the same key linkable by anyone who
/// knows that key.
/// </remarks>
public sealed class P256TagRecipient : IRecipient
{
    private const string Hrp = "age1tag";

    private readonly byte[] _compressedPoint; // 33 bytes, as encoded
    private readonly byte[] _point; // 65 bytes, as HPKE takes it

    private P256TagRecipient(byte[] compressedPoint, byte[] point)
    {
        _compressedPoint = compressedPoint;
        _point = point;
    }

    /// <summary>Parses a Bech32-encoded recipient (<c>age1tag1…</c>, lowercase).</summary>
    /// <exception cref="FormatException">The string is not a valid tagged P-256 recipient.</exception>
    public static P256TagRecipient Parse(string s)
    {
        var (hrp, data) = Bech32.Decode(s);

        if (hrp != Hrp)
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");

        if (s != s.ToLowerInvariant())
            throw new FormatException("age recipient must be lowercase");

        return new P256TagRecipient(data, DhKemP256.Decompress(data));
    }

    /// <summary>Returns the Bech32-encoded recipient string (<c>age1tag1…</c>).</summary>
    public override string ToString() =>
        Bech32.Encode(Hrp, _compressedPoint);

    /// <summary>Wraps the file key in a <c>p256tag</c> stanza.</summary>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) =>
        [WrapOne(fileKey)];

    private Stanza WrapOne(ReadOnlySpan<byte> fileKey) =>
        TaggedStanza.Wrap(AgeProtocol.P256TagStanzaType, DhKemP256.KemId, AgeProtocol.P256TagHpkeInfo,
            DhKemP256.Encapsulate(_point, new SecureRandom()), _compressedPoint, fileKey);
}
