using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace AgeSharp.Crypto;

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
    internal const ushort KemId = 0x0050;

    /// <summary>The public key: an ML-KEM-768 encapsulation key, then an uncompressed P-256 point.</summary>
    internal const int PublicKeySize = MlKem768EncapsulationKey.Size + DhKemP256.UncompressedPointSize;

    /// <summary>The encapsulated key: the ML-KEM-768 ciphertext, then the ephemeral P-256 point.</summary>
    internal const int EncSize = MlKem768EncapsulationKey.CiphertextSize + DhKemP256.UncompressedPointSize;

    /// <summary>Where the P-256 point starts in the public key.</summary>
    internal const int PointOffset = MlKem768EncapsulationKey.Size;

    private static readonly byte[] Label = "MLKEM768-P256"u8.ToArray();

    /// <summary>Checks that both halves of a public key are well formed.</summary>
    /// <exception cref="FormatException">They are not.</exception>
    internal static void ValidatePublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != PublicKeySize)
            throw new FormatException($"an MLKEM768-P256 public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        MlKem768EncapsulationKey.Decode(publicKey[..PointOffset]);
        DhKemP256.ValidateUncompressed(publicKey[PointOffset..]);
    }

    /// <summary>
    /// Encapsulates to a public key that <see cref="ValidatePublicKey"/> accepted. The ML-KEM
    /// randomness is drawn from <paramref name="random"/>. The P-256 ephemeral key is generated
    /// by the backend, unless a <paramref name="p256ScalarSource"/> is given (see
    /// <see cref="DhKemP256.DiffieHellman"/>); the known-answer vectors pass the same source for
    /// both, which then gives the ML-KEM randomness first, as they order them.
    /// </summary>
    public static (byte[] SharedSecret, byte[] Enc) Encapsulate(byte[] publicKey, SecureRandom random, SecureRandom? p256ScalarSource = null, P256Backend? backend = null)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}", nameof(publicKey));

        var pointT = publicKey[PointOffset..];
        var (ctPq, ssPq) = MlKem768EncapsulationKey.Decode(publicKey.AsSpan(0, PointOffset)).Encapsulate(random);
        byte[]? ssT = null;

        try
        {
            (ssT, var ctT) = DhKemP256.DiffieHellman(pointT, p256ScalarSource, backend ?? DhKemP256.DefaultBackend);
            return (HybridKem.CombineSharedSecrets(Label, ssPq, ssT, ctT, pointT), [.. ctPq, .. ctT]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssPq);

            if (ssT is not null)
                CryptographicOperations.ZeroMemory(ssT);
        }
    }
}
