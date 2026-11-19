using System.Text.Json;
using Age.Crypto;
using Age.Format;
using Age.Recipients;
using Org.BouncyCastle.Security;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The tagged recipient types (<c>age1tag1…</c>, <c>age1tagpq1…</c>), which encrypt to keys held
/// on hardware. Encryption only, as in go-age and rage: decrypting is the job of the plugin that
/// talks to the hardware.
/// </summary>
/// <remarks>
/// The HPKE parts are checked against published known-answer vectors (RFC 9180 for P-256, the
/// filippo.io/hpke vectors for MLKEM768-P256). That go-age's own tag identities decrypt what these
/// recipients produce was checked outside the suite, with go-age's tag/internal/tagtest.
/// </remarks>
public class TaggedRecipientTests
{
    // --- HPKE: known-answer vectors ---------------------------------------------------------

    [Fact]
    public void DhKemP256_AndTheHpkeKeySchedule_MatchRfc9180()
    {
        var v = Vector("p256-hkdfsha256-chacha20poly1305.json");

        var (sharedSecret, enc) = DhKemP256.Encapsulate(Hex(v, "pkRm"), ephemeralScalar: Hex(v, "skEm"));
        var (key, baseNonce) = HpkeHelper.KeyScheduleBase(DhKemP256.Id, sharedSecret, Hex(v, "info"));

        Assert.Equal(Hex(v, "enc"), enc);
        Assert.Equal(Hex(v, "shared_secret"), sharedSecret);
        Assert.Equal(Hex(v, "key"), key);
        Assert.Equal(Hex(v, "base_nonce"), baseNonce);
    }

    // The RFC's encryptions carry associated data, which age never uses and this library's AEAD
    // does not take. So the seal is checked against the key schedule the vector pinned above:
    // the first message is ChaCha20-Poly1305 under that key and base nonce.
    [SkippableFact]
    public void HpkeSeal_EncryptsUnderTheKeyScheduleKeyAndBaseNonce()
    {
        Skip.IfNot(System.Security.Cryptography.ChaCha20Poly1305.IsSupported, "no platform ChaCha20-Poly1305 to compare with");

        var v = Vector("p256-hkdfsha256-chacha20poly1305.json");
        var plaintext = "file key bytes!!"u8.ToArray();

        var ciphertext = HpkeHelper.SealBase(DhKemP256.Id, Hex(v, "shared_secret"), Hex(v, "info"), plaintext);

        var expected = new byte[plaintext.Length + 16];
        using var chacha = new System.Security.Cryptography.ChaCha20Poly1305(Hex(v, "key"));
        chacha.Encrypt(Hex(v, "base_nonce"), plaintext, expected.AsSpan(0, plaintext.Length), expected.AsSpan(plaintext.Length));

        Assert.Equal(expected, ciphertext);
    }

    [Fact]
    public void MlKem768P256_MatchesTheHpkePqVector()
    {
        var v = Vector("mlkem768p256.json");
        var ikmE = Hex(v, "ikmE");

        // ikmE[0:32] is the ML-KEM-768 encapsulation randomness, ikmE[32:64] the P-256 scalar.
        var (sharedSecret, enc) = MlKem768P256.Encapsulate(Hex(v, "pkRm"),
            mlKemRandom: new FixedRandom(ikmE[..32]), ephemeralScalar: ikmE[32..64]);

        Assert.Equal(Hex(v, "enc"), enc);
        Assert.Equal(Hex(v, "shared_secret"), sharedSecret);
    }

    // --- Recipients ---------------------------------------------------------------------------

    [Fact]
    public void GoAgesTestRecipients_ParseAndRoundTrip()
    {
        var (classic, hybrid) = GoAgeRecipients();

        Assert.Equal(classic, P256TagRecipient.Parse(classic).ToString());
        Assert.Equal(hybrid, MlKem768P256TagRecipient.Parse(hybrid).ToString());
    }

    [Fact]
    public void ARecipientsFile_ReadsTaggedRecipientsNatively_NotAsPlugins()
    {
        var (classic, hybrid) = GoAgeRecipients();

        var recipients = AgeKeygen.ParseRecipientsFile($"# hardware keys\n{classic}\n{hybrid}\n");

        Assert.IsType<P256TagRecipient>(recipients[0]);
        Assert.IsType<MlKem768P256TagRecipient>(recipients[1]);
    }

    public static TheoryData<string, Func<string>> MalformedClassicRecipients => new()
    {
        { "32 bytes", () => Bech32.Encode("age1tag", new byte[32]) },
        { "not a point encoding", () => Bech32.Encode("age1tag", [0x05, .. new byte[32]]) },
        { "uncompressed", () => Bech32.Encode("age1tag", Uncompressed(GoAgeRecipients().Classic)) },
        { "an x with no point on the curve", () => Bech32.Encode("age1tag", NotOnTheCurve()) },
        { "the hybrid's prefix", () => Bech32.Encode("age1tagpq", Bech32.Decode(GoAgeRecipients().Classic).Data) },
        { "uppercase", () => GoAgeRecipients().Classic.ToUpperInvariant() },
    };

    [Theory]
    [MemberData(nameof(MalformedClassicRecipients))]
    public void AMalformedClassicRecipient_IsAFormatException(string why, Func<string> recipient)
    {
        _ = why;
        Assert.Throws<FormatException>(() => P256TagRecipient.Parse(recipient()));
    }

    public static TheoryData<string, Func<string>> MalformedHybridRecipients => new()
    {
        { "1248 bytes", () => Bech32.Encode("age1tagpq", HybridKey()[..^1]) },
        { "a compressed point", () => Bech32.Encode("age1tagpq", [.. HybridKey()[..1184], .. Bech32.Decode(GoAgeRecipients().Classic).Data]) },
        { "a point not on the curve", () => Bech32.Encode("age1tagpq", [.. HybridKey()[..1184], 0x04, .. new byte[64]]) },
        { "a point with a wrong prefix", () => Bech32.Encode("age1tagpq", [.. HybridKey()[..1184], 0x05, .. HybridKey()[1185..]]) },
        { "an ML-KEM coefficient out of range", () => Bech32.Encode("age1tagpq", WithFirstCoefficient(HybridKey(), 0xFFF)) },
        { "the classic prefix", () => Bech32.Encode("age1tag", HybridKey()) },
        { "uppercase", () => GoAgeRecipients().Hybrid.ToUpperInvariant() },
    };

    [Theory]
    [MemberData(nameof(MalformedHybridRecipients))]
    public void AMalformedHybridRecipient_IsAFormatException(string why, Func<string> recipient)
    {
        _ = why;
        Assert.Throws<FormatException>(() => MlKem768P256TagRecipient.Parse(recipient()));
    }

    // An ephemeral scalar must lie in [1, n-1]; zero would make the ephemeral point infinity.
    [Fact]
    public void TheHybridKem_RefusesAPublicKeyOfTheWrongLength()
    {
        Assert.Throws<ArgumentException>(() => MlKem768P256.Encapsulate(HybridKey()[..^1]));
    }

    [Fact]
    public void AnEphemeralScalarOutOfRange_IsRefused()
    {
        var point = Uncompressed(GoAgeRecipients().Classic);

        Assert.Throws<ArgumentException>(() => DhKemP256.Encapsulate(point, ephemeralScalar: new byte[32]));
        Assert.Throws<ArgumentException>(() => DhKemP256.Encapsulate(point, ephemeralScalar: new byte[31]));
    }

    // --- Stanzas ------------------------------------------------------------------------------

    [Fact]
    public void P256Tag_WrapsTheFileKeyInTheSpecsStanza()
    {
        var recipient = P256TagRecipient.Parse(GoAgeRecipients().Classic);

        var stanza = recipient.Wrap(new byte[16]);

        // p256tag, a 4-byte tag, a 65-byte enc, and a 32-byte body (file key and Poly1305 tag).
        Assert.Equal("p256tag", stanza.Type);
        Assert.Equal(2, stanza.Args.Count);
        Assert.Equal(4, Base64Unpadded.Decode(stanza.Args[0]).Length);
        Assert.Equal(65, Base64Unpadded.Decode(stanza.Args[1]).Length);
        Assert.Equal(32, stanza.Body.Length);
        Assert.Null(recipient.Label);
    }

    [Fact]
    public void MlKem768P256Tag_WrapsTheFileKeyInTheSpecsStanza()
    {
        var recipient = MlKem768P256TagRecipient.Parse(GoAgeRecipients().Hybrid);

        var stanza = recipient.Wrap(new byte[16]);

        Assert.Equal("mlkem768p256tag", stanza.Type);
        Assert.Equal(2, stanza.Args.Count);
        Assert.Equal(4, Base64Unpadded.Decode(stanza.Args[0]).Length);
        Assert.Equal(1153, Base64Unpadded.Decode(stanza.Args[1]).Length);
        Assert.Equal(32, stanza.Body.Length);
        Assert.Equal("postquantum", recipient.Label);
    }

    [Fact]
    public void TheTag_IsTheSpecsHkdfExtract_OverEncAndTheRecipientHash()
    {
        // tag = HKDF-Extract-SHA-256(ikm = enc || SHA-256(recipient)[:4], salt = label)[:4], with
        // the hybrid hashing only its P-256 point.
        var classic = P256TagRecipient.Parse(GoAgeRecipients().Classic);
        var hybrid = MlKem768P256TagRecipient.Parse(GoAgeRecipients().Hybrid);

        AssertTag(classic.Wrap(new byte[16]), "age-encryption.org/p256tag", Bech32.Decode(GoAgeRecipients().Classic).Data);
        AssertTag(hybrid.Wrap(new byte[16]), "age-encryption.org/mlkem768p256tag", Bech32.Decode(GoAgeRecipients().Hybrid).Data[1184..]);

        static void AssertTag(Stanza stanza, string label, byte[] hashed)
        {
            var enc = Base64Unpadded.Decode(stanza.Args[1]);
            var ikm = (byte[])[.. enc, .. System.Security.Cryptography.SHA256.HashData(hashed)[..4]];
            var expected = System.Security.Cryptography.HKDF.Extract(System.Security.Cryptography.HashAlgorithmName.SHA256,
                ikm, System.Text.Encoding.ASCII.GetBytes(label))[..4];

            Assert.Equal(expected, Base64Unpadded.Decode(stanza.Args[0]));
        }
    }

    [Fact]
    public void TheHybrid_IsNotMixedWithClassicRecipients_AsAgeRequires()
    {
        var hybrid = MlKem768P256TagRecipient.Parse(GoAgeRecipients().Hybrid);
        var classic = P256TagRecipient.Parse(GoAgeRecipients().Classic);
        using var x25519 = X25519Identity.Generate();

        Assert.Throws<AgeException>(() => AgeEncrypt.Encrypt(new MemoryStream([1]), new MemoryStream(), hybrid, classic));
        Assert.Throws<AgeException>(() => AgeEncrypt.Encrypt(new MemoryStream([1]), new MemoryStream(), hybrid, x25519.Recipient));

        // Two post-quantum recipients, and two classic ones, are fine.
        using var pq = MlKem768X25519Identity.Generate();
        AgeEncrypt.Encrypt(new MemoryStream([1]), new MemoryStream(), hybrid, pq.Recipient);
        AgeEncrypt.Encrypt(new MemoryStream([1]), new MemoryStream(), classic, x25519.Recipient);
    }

    // --- Reading files that carry tagged stanzas ---------------------------------------------

    // This library only encrypts to tagged recipients, but must still read a file that has
    // their stanzas next to its own.
    [Fact]
    public void AFileForATaggedAndAnX25519Recipient_DecryptsWithTheX25519Identity()
    {
        using var x25519 = X25519Identity.Generate();
        var classic = P256TagRecipient.Parse(GoAgeRecipients().Classic);

        Assert.Equal(Plaintext, Decrypt(Encrypt(classic, x25519.Recipient), x25519));
    }

    [Fact]
    public void AFileForTheTaggedHybridAndAnMlKem768X25519Recipient_DecryptsWithTheMlKemIdentity()
    {
        using var pq = MlKem768X25519Identity.Generate();
        var hybrid = MlKem768P256TagRecipient.Parse(GoAgeRecipients().Hybrid);

        Assert.Equal(Plaintext, Decrypt(Encrypt(pq.Recipient, hybrid), pq));
    }

    [Fact]
    public void AFileOnlyForTaggedRecipients_IsNoMatchForAnotherIdentity_NotAMalformedHeader()
    {
        using var unrelated = X25519Identity.Generate();
        var ciphertext = Encrypt(P256TagRecipient.Parse(GoAgeRecipients().Classic));

        Assert.Throws<NoIdentityMatchException>(() => Decrypt(ciphertext, unrelated));
    }

    private static readonly byte[] Plaintext = "for a hardware key"u8.ToArray();

    private static byte[] Encrypt(params IRecipient[] recipients)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(Plaintext), output, recipients);
        return output.ToArray();
    }

    private static byte[] Decrypt(byte[] ciphertext, IIdentity identity)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(new MemoryStream(ciphertext), output, identity);
        return output.ToArray();
    }

    // --- Helpers ------------------------------------------------------------------------------

    private static (string Classic, string Hybrid) GoAgeRecipients()
    {
        var lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "TestData", "Hpke", "goage-tagtest-recipients.txt"))
            .Select(line => line.Split(' ')).ToDictionary(f => f[0], f => f[1]);
        return (lines["p256tag"], lines["mlkem768p256tag"]);
    }

    private static byte[] HybridKey() => Bech32.Decode(GoAgeRecipients().Hybrid).Data;

    // A compressed encoding whose x has no y on P-256: about half of all x do. The first such x
    // counting up from 1 keeps the case fixed.
    private static byte[] NotOnTheCurve()
    {
        var curve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("secp256r1").Curve;

        for (byte x = 1; ; x++)
        {
            byte[] encoded = [0x02, .. new byte[31], x];

            try
            {
                curve.DecodePoint(encoded);
            }
            catch (ArgumentException)
            {
                return encoded;
            }
        }
    }

    private static byte[] Uncompressed(string classic) =>
        Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("secp256r1").Curve
            .DecodePoint(Bech32.Decode(classic).Data).GetEncoded(false);

    private static byte[] WithFirstCoefficient(byte[] key, int coefficient)
    {
        var changed = (byte[])key.Clone();
        changed[0] = (byte)coefficient;
        changed[1] = (byte)((changed[1] & 0xF0) | (coefficient >> 8));
        return changed;
    }

    private static JsonElement Vector(string name) =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "Hpke", name))).RootElement;

    private static byte[] Hex(JsonElement element, string property) => Convert.FromHexString(element.GetProperty(property).GetString()!);

    /// <summary>Hands out the given bytes as its randomness, for a deterministic encapsulation.</summary>
    private sealed class FixedRandom(byte[] bytes) : SecureRandom
    {
        private int _position;

        public override void NextBytes(byte[] buffer) => NextBytes(buffer, 0, buffer.Length);

        public override void NextBytes(byte[] buffer, int start, int length) => NextBytes(buffer.AsSpan(start, length));

        public override void NextBytes(Span<byte> buffer)
        {
            bytes.AsSpan(_position, buffer.Length).CopyTo(buffer);
            _position += buffer.Length;
        }
    }
}
