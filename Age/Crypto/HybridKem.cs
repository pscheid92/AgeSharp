using Org.BouncyCastle.Crypto.Digests;

namespace Age.Crypto;

/// <summary>
/// What the two hybrid KEMs, X-Wing and MLKEM768-P256, have in common: ML-KEM-768 next to a
/// classical exchange, and one shared secret from both.
/// </summary>
internal static class HybridKem
{
    private const int SharedSecretSize = 32;

    /// <summary>
    /// The combiner both use, each with its own label:
    /// <c>SHA3-256(ss_PQ || ss_T || ct_T || pk_T || label)</c>, where T is the classical half.
    /// </summary>
    /// <remarks>
    /// As in X-Wing (draft-connolly-cfrg-xwing-kem) and draft-ietf-hpke-pq, and in
    /// filippo.io/hpke v0.4.0, which go-age uses.
    /// </remarks>
    public static byte[] CombineSharedSecrets(ReadOnlySpan<byte> label, byte[] postQuantumSecret, byte[] classicalSecret,
        byte[] classicalCiphertext, ReadOnlySpan<byte> classicalPublicKey)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(postQuantumSecret);
        sha3.BlockUpdate(classicalSecret);
        sha3.BlockUpdate(classicalCiphertext);
        sha3.BlockUpdate(classicalPublicKey);
        sha3.BlockUpdate(label);

        var result = new byte[SharedSecretSize];
        sha3.DoFinal(result);
        return result;
    }
}
