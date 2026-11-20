using AgeSharp.Crypto;
using AgeSharp;
using Org.BouncyCastle.Security;

namespace AgeSharp;

/// <summary>
/// A tagged post-quantum recipient (<c>age1tagpq1…</c>): ML-KEM-768 hybridised with P-256, used
/// to encrypt to a key held on hardware. Instances are immutable and safe to share.
/// </summary>
/// <remarks>
/// Encryption only, as in go-age and rage: decrypting is the job of the plugin that talks to
/// the hardware (through <see cref="PluginIdentity"/>). The file key is sealed with HPKE, the
/// MLKEM768-P256 KEM of draft-ietf-hpke-pq with ChaCha20-Poly1305, and the stanza carries a tag
/// computed over the P-256 point only, so the hardware can recognise it without its ML-KEM key. That
/// tag makes files encrypted to the same key linkable by anyone who knows that key.
/// </remarks>
public sealed class MlKem768P256TagRecipient : IRecipientWithLabels
{
    private const string Hrp = "age1tagpq";

    private readonly byte[] _publicKey; // 1249 bytes: ML-KEM-768 key, then an uncompressed P-256 point

    private MlKem768P256TagRecipient(byte[] publicKey) =>
        _publicKey = publicKey;

    private static readonly IReadOnlyCollection<string> PostQuantumLabels = Array.AsReadOnly(["postquantum"]);

    /// <summary>Parses a Bech32-encoded recipient (<c>age1tagpq1…</c>, lowercase).</summary>
    /// <exception cref="FormatException">The string is not a valid tagged post-quantum recipient.</exception>
    public static MlKem768P256TagRecipient Parse(string s)
    {
        var (hrp, data) = Bech32.Decode(s);

        if (hrp != Hrp)
            throw new FormatException($"expected HRP '{Hrp}', got '{hrp}'");

        if (s != s.ToLowerInvariant())
            throw new FormatException("age recipient must be lowercase");

        MlKem768P256.ValidatePublicKey(data);
        return new MlKem768P256TagRecipient(data);
    }

    /// <summary>Returns the Bech32-encoded recipient string (<c>age1tagpq1…</c>).</summary>
    public override string ToString() =>
        Bech32.Encode(Hrp, _publicKey);

    /// <summary>
    /// Wraps the file key, with the <c>postquantum</c> label: a file encrypted to this
    /// recipient cannot also be encrypted to a classical one, which would void the
    /// post-quantum guarantee.
    /// </summary>
    public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) =>
        new([WrapOne(fileKey)], PostQuantumLabels);

    /// <summary>Wraps the file key in an <c>mlkem768p256tag</c> stanza.</summary>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) =>
        WrapWithLabels(fileKey).Stanzas;

    private Stanza WrapOne(ReadOnlySpan<byte> fileKey) =>
        TaggedStanza.Wrap(AgeProtocol.MlKem768P256TagStanzaType, MlKem768P256.KemId, AgeProtocol.MlKem768P256TagHpkeInfo,
            MlKem768P256.Encapsulate(_publicKey, new SecureRandom()), _publicKey.AsSpan(MlKem768P256.PointOffset), fileKey);
}
