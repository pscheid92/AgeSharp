using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Crypto;

/// <summary>
/// The MLKEM768-P256 hybrid KEM of draft-ietf-hpke-pq, for encapsulation only: what the
/// mlkem768p256tag recipient type seals to. The same construction as X-Wing, with P-256 in place
/// of X25519 and its own label.
/// </summary>
/// <remarks>
/// Ported from filippo.io/hpke v0.4.0 (pq.go, hybridPublicKey.encap and hybridKEM.sharedSecret),
/// which go-age uses, on BouncyCastle's ML-KEM-768 and P-256, and checked against that module's
/// hpke-pq test vectors.
/// </remarks>
internal static class MlKem768P256
{
    /// <summary>The HPKE KEM ID of MLKEM768-P256.</summary>
    internal const ushort Id = 0x0050;

    private const int MlKemPublicKeySize = 1184;
    private const int MlKemCiphertextSize = 1088;
    private const int SharedSecretSize = 32;

    /// <summary>The public key: an ML-KEM-768 encapsulation key, then an uncompressed P-256 point.</summary>
    internal const int PublicKeySize = MlKemPublicKeySize + DhKemP256.PointSize;

    /// <summary>The encapsulated key: the ML-KEM-768 ciphertext, then the ephemeral P-256 point.</summary>
    internal const int EncSize = MlKemCiphertextSize + DhKemP256.PointSize;

    /// <summary>Where the P-256 point starts in the public key.</summary>
    internal const int PointOffset = MlKemPublicKeySize;

    private static readonly byte[] Label = "MLKEM768-P256"u8.ToArray();

    /// <summary>Checks that both halves of a public key are well formed.</summary>
    /// <exception cref="FormatException">They are not.</exception>
    internal static void ValidatePublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != PublicKeySize)
            throw new FormatException($"an MLKEM768-P256 public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        DecodeMlKem(publicKey[..MlKemPublicKeySize]);
        DhKemP256.ValidateUncompressed(publicKey[PointOffset..]);
    }

    /// <summary>Encapsulates to a public key that <see cref="ValidatePublicKey"/> accepted.</summary>
    public static (byte[] SharedSecret, byte[] Enc) Encapsulate(byte[] publicKey) =>
        Encapsulate(publicKey, new SecureRandom(), ephemeralScalar: null);

    /// <summary>
    /// Encapsulates with the given ML-KEM randomness and P-256 ephemeral scalar (random when
    /// null) — which is how the known-answer vectors are reproduced.
    /// </summary>
    internal static (byte[] SharedSecret, byte[] Enc) Encapsulate(byte[] publicKey, SecureRandom mlKemRandom, byte[]? ephemeralScalar)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}", nameof(publicKey));

        var pointT = publicKey[PointOffset..];

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(DecodeMlKem(publicKey.AsSpan(0, MlKemPublicKeySize)), mlKemRandom));

        var ctPq = new byte[MlKemCiphertextSize];
        var ssPq = new byte[SharedSecretSize];
        byte[]? ssT = null;

        try
        {
            encapsulator.Encapsulate(ctPq, 0, MlKemCiphertextSize, ssPq, 0, SharedSecretSize);

            (ssT, var ctT) = DhKemP256.DiffieHellman(pointT, ephemeralScalar);

            // ss = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label)
            var sharedSecret = new byte[SharedSecretSize];
            var sha3 = new Sha3Digest(256);
            sha3.BlockUpdate(ssPq, 0, ssPq.Length);
            sha3.BlockUpdate(ssT, 0, ssT.Length);
            sha3.BlockUpdate(ctT, 0, ctT.Length);
            sha3.BlockUpdate(pointT, 0, pointT.Length);
            sha3.BlockUpdate(Label, 0, Label.Length);
            sha3.DoFinal(sharedSecret, 0);

            return (sharedSecret, [.. ctPq, .. ctT]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssPq);

            if (ssT is not null)
                CryptographicOperations.ZeroMemory(ssT);
        }
    }

    private static MLKemPublicKeyParameters DecodeMlKem(ReadOnlySpan<byte> encapsulationKey)
    {
        MLKemPublicKeyParameters key;

        try
        {
            key = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, encapsulationKey.ToArray());
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw new FormatException($"invalid ML-KEM-768 encapsulation key: {ex.Message}", ex);
        }

        // FromEncoding does not check the coefficients; FIPS 203 requires every one below q.
        return XWing.CoefficientsAreInRange(encapsulationKey[..XWing.CoefficientBytes])
            ? key
            : throw new FormatException("invalid ML-KEM-768 encapsulation key: a coefficient is not less than the modulus");
    }
}
