using System.Diagnostics.CodeAnalysis;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// A post-quantum ML-KEM-768-X25519 hybrid recipient (<c>age1pq1…</c>), used to
/// encrypt. Instances are immutable and safe to share.
/// </summary>
public sealed class MlKem768X25519Recipient : IRecipientWithLabels, IParsable<MlKem768X25519Recipient>
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
    private static readonly string[] PostQuantumLabels = ["postquantum"];

    /// <summary>
    /// Wraps the file key and attaches the <c>postquantum</c> label, so this
    /// recipient can only be combined with other post-quantum-secure recipients
    /// (mixing with a classical recipient would leave the file vulnerable to a
    /// quantum attacker who breaks the classical stanza).
    /// </summary>
    public (Stanza stanza, IReadOnlyCollection<string> labels) WrapWithLabels(ReadOnlySpan<byte> fileKey) =>
        (Wrap(fileKey), PostQuantumLabels);

    /// <summary>Parses a bech32-encoded recipient (<c>age1pq1…</c>, lowercase).</summary>
    /// <exception cref="AgeFormatException">The string is not a valid ML-KEM-768-X25519 recipient.</exception>
    public static MlKem768X25519Recipient Parse(string s) =>
        new(ParseHelpers.DecodeRecipientKey(s, Hrp, XWing.PublicKeySize, "ML-KEM-768-X25519 public key"));

    /// <summary>
    /// Tries to parse a bech32-encoded recipient (<c>age1pq1…</c>). Returns false
    /// instead of throwing when the input is null or malformed.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? s, [MaybeNullWhen(false)] out MlKem768X25519Recipient result) =>
        ParseHelpers.TryParse(s, Parse, out result);

    static MlKem768X25519Recipient IParsable<MlKem768X25519Recipient>.Parse(string s, IFormatProvider? provider) =>
        Parse(s);

    static bool IParsable<MlKem768X25519Recipient>.TryParse(string? s, IFormatProvider? provider, [MaybeNullWhen(false)] out MlKem768X25519Recipient result) =>
        TryParse(s, out result);

    /// <summary>Returns the bech32-encoded recipient string (<c>age1pq1…</c>).</summary>
    public override string ToString() =>
        Bech32.Encode(Hrp, _publicKey);

    /// <summary>Wraps the file key for this recipient via X-Wing HPKE (ML-KEM-768 + X25519).</summary>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var (enc, ct) = HpkeHelper.SealBase(_publicKey, AgeProtocol.MlKemHpkeInfo, fileKey.ToArray());
        var encB64 = Base64Unpadded.Encode(enc);
        return new Stanza(AgeProtocol.MlKemStanzaType, [encB64], ct);
    }
}