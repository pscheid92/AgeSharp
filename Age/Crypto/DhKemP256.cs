using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
using Org.BouncyCastle.Security;

namespace AgeSharp.Crypto;

/// <summary>
/// DHKEM(P-256, HKDF-SHA256), the KEM of RFC 9180, section 4.1, for encapsulation only: what
/// the p256tag recipient type seals to.
/// </summary>
/// <remarks>
/// Ported from filippo.io/hpke v0.4.0 (kem.go, dhKEMPublicKey.encap), which go-age uses, on
/// BouncyCastle's P-256, and checked against the RFC 9180 test vectors.
/// </remarks>
internal static class DhKemP256
{
    /// <summary>The HPKE KEM ID of DHKEM(P-256, HKDF-SHA256).</summary>
    internal const ushort KemId = 0x0010;

    /// <summary>An uncompressed P-256 point, as public keys and enc are serialised.</summary>
    internal const int UncompressedPointSize = 65;

    /// <summary>A compressed P-256 point.</summary>
    internal const int CompressedPointSize = 33;

    private const int SharedSecretSize = 32;
    private const int ScalarSize = 32;

    // BouncyCastle's custom P-256 (SecP256R1Curve), with specialised field arithmetic, rather
    // than the generic curve ECNamedCurveTable returns.
    private static readonly X9ECParameters Curve = CustomNamedCurves.GetByName("secp256r1");

    private static readonly FixedPointCombMultiplier GeneratorMultiplier = new();

    // suite_id = "KEM" || I2OSP(kem_id, 2), as DHKEM's ExtractAndExpand uses.
    private static readonly byte[] KemSuiteId = [(byte)'K', (byte)'E', (byte)'M', KemId >> 8, KemId & 0xff];

    /// <summary>
    /// Encapsulates to <paramref name="recipientPoint"/>, an uncompressed P-256 point, with the
    /// ephemeral key drawn from <paramref name="random"/>.
    /// </summary>
    public static (byte[] SharedSecret, byte[] Enc) Encapsulate(byte[] recipientPoint, SecureRandom random)
    {
        var (dh, enc) = DiffieHellman(recipientPoint, random);

        try
        {
            // kem_context = enc || pkRm
            byte[] kemContext = [.. enc, .. recipientPoint];
            var eaePrk = HpkeHelper.LabeledExtract(KemSuiteId, [], "eae_prk", dh);

            try
            {
                return (HpkeHelper.LabeledExpand(KemSuiteId, eaePrk, "shared_secret", kemContext, SharedSecretSize), enc);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(eaePrk);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dh);
        }
    }

    /// <summary>
    /// An ephemeral key pair's ECDH with <paramref name="recipientPoint"/>: the shared x
    /// coordinate (32 bytes) and the ephemeral public point, uncompressed. Shared with the
    /// MLKEM768-P256 hybrid, whose P-256 half is the same exchange.
    /// </summary>
    internal static (byte[] SharedX, byte[] EphemeralPoint) DiffieHellman(byte[] recipientPoint, SecureRandom random)
    {
        var recipient = DecodeUncompressed(recipientPoint);
        var scalar = RandomScalar(random);

        var shared = recipient.Multiply(scalar).Normalize();
        if (shared.IsInfinity)
            throw new CryptographicException("P-256 ECDH produced the point at infinity");

        // The generator goes through BouncyCastle's fixed-point comb, which is more regular than
        // the default wNAF. Neither is constant-time as go-age's P-256 is; the scalar is ephemeral
        // and used for one stanza.
        var ephemeralPoint = GeneratorMultiplier.Multiply(Curve.G, scalar).Normalize().GetEncoded(compressed: false);
        return (shared.AffineXCoord.GetEncoded(), ephemeralPoint);
    }

    /// <summary>
    /// The uncompressed form of a compressed P-256 point, as the p256tag recipient is encoded.
    /// </summary>
    /// <exception cref="FormatException">The bytes are not a compressed point on P-256.</exception>
    internal static byte[] Decompress(ReadOnlySpan<byte> compressed)
    {
        if (compressed.Length != CompressedPointSize || compressed[0] is not (0x02 or 0x03))
            throw new FormatException($"a P-256 public key must be a {CompressedPointSize}-byte compressed point");

        return Decode(compressed).GetEncoded(compressed: false);
    }

    /// <summary>Checks that the bytes are an uncompressed point on P-256.</summary>
    /// <exception cref="FormatException">They are not.</exception>
    internal static void ValidateUncompressed(ReadOnlySpan<byte> point) => DecodeUncompressed(point);

    private static ECPoint DecodeUncompressed(ReadOnlySpan<byte> point)
    {
        if (point.Length != UncompressedPointSize || point[0] != 0x04)
            throw new FormatException($"a P-256 public key must be a {UncompressedPointSize}-byte uncompressed point");

        return Decode(point);
    }

    private static ECPoint Decode(ReadOnlySpan<byte> encoded)
    {
        ECPoint point;

        try
        {
            point = Curve.Curve.DecodePoint(encoded.ToArray());
        }
        catch (Exception ex) when (ex is ArgumentException or ArithmeticException or FormatException)
        {
            throw new FormatException($"not a point on P-256: {ex.Message}", ex);
        }

        if (point.IsInfinity || !point.IsValid())
            throw new FormatException("not a point on P-256");

        return point;
    }

    // A scalar uniform in [1, n-1], by rejection sampling as Go's crypto/ecdh does. A test that
    // reproduces a known-answer vector supplies the vector's scalar as the random bytes.
    private static BigInteger RandomScalar(SecureRandom random)
    {
        var bytes = new byte[ScalarSize];

        try
        {
            while (true)
            {
                random.NextBytes(bytes);
                var scalar = new BigInteger(1, bytes);

                if (scalar.SignValue > 0 && scalar.CompareTo(Curve.N) < 0)
                    return scalar;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
