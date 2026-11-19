using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Crypto;

/// <summary>
/// X-Wing (MLKEM768-X25519, draft-connolly-cfrg-xwing-kem): what the mlkem768x25519 recipient
/// type seals to.
/// </summary>
internal static class XWing
{
    // X-Wing combiner label: ASCII `\.//^\` (the X-Wing spec domain separator)
    private static readonly byte[] XWingLabel = @"\.//^\"u8.ToArray();

    private const int MlKemPublicKeySize = MlKem768EncapsulationKey.Size;
    private const int MlKemCiphertextSize = MlKem768EncapsulationKey.CiphertextSize;
    private const int X25519KeySize = 32;
    private const int SharedSecretSize = 32;
    private const int MlKemSeedSize = 64;

    /// <summary>The HPKE KEM ID of X-Wing (MLKEM768-X25519).</summary>
    internal const ushort KemId = 0x647a;

    internal const int PublicKeySize = MlKemPublicKeySize + X25519KeySize;
    internal const int EncSize = MlKemCiphertextSize + X25519KeySize;

    public static byte[] GeneratePublicKey(byte[] seed)
    {
        var (mlKemPrivate, seedPq, x25519Private, _) = ExpandSeed(seed);

        try
        {
            var pkM = mlKemPrivate.GetPublicKeyEncoded(); // 1184 bytes (see MlKemPublicKeySize)
            var pkX = x25519Private.GeneratePublicKey().GetEncoded(); // 32 bytes (see X25519KeySize)

            var publicKey = new byte[PublicKeySize];
            pkM.CopyTo(publicKey, 0);
            pkX.CopyTo(publicKey, MlKemPublicKeySize);
            return publicKey;
        }
        finally
        {
            // seedPq is the ML-KEM-768 private seed (d,z).
            CryptographicOperations.ZeroMemory(seedPq);
        }
    }

    /// <summary>
    ///     Checks that the ML-KEM half of an X-Wing public key actually decodes, so a malformed
    ///     recipient is rejected at parse time rather than partway through an encryption.
    /// </summary>
    /// <exception cref="FormatException">The ML-KEM-768 encapsulation key is not well formed.</exception>
    public static void ValidatePublicKey(byte[] publicKey)
    {
        if (publicKey.Length != PublicKeySize)
            throw new FormatException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        MlKem768EncapsulationKey.Decode(publicKey.AsSpan(0, MlKemPublicKeySize));
    }

    /// <summary>Encapsulates to a public key, with randomness from <paramref name="random"/>.</summary>
    /// <exception cref="AgeHeaderException">
    /// The ML-KEM-768 half is malformed. This is reachable without going through
    /// <see cref="ValidatePublicKey"/>, so it checks again rather than trusting the caller.
    /// </exception>
    public static (byte[] SharedSecret, byte[] Enc) Encapsulate(byte[] publicKey, SecureRandom random)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        var pkX = publicKey[MlKemPublicKeySize..];
        MlKem768EncapsulationKey mlKemKey;

        try
        {
            mlKemKey = MlKem768EncapsulationKey.Decode(publicKey.AsSpan(0, MlKemPublicKeySize));
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException(ex.Message, ex);
        }

        var (ctM, ssM) = mlKemKey.Encapsulate(random);

        // X25519 ephemeral DH, through the same guarded helper Decapsulate uses.
        var ekX = new X25519PrivateKeyParameters(random);
        var ctX = ekX.GeneratePublicKey().GetEncoded();
        var ssX = new byte[SharedSecretSize];

        try
        {
            CryptoHelper.X25519Agree(ekX, new X25519PublicKeyParameters(pkX), ssX);
            return (HybridKem.CombineSharedSecrets(XWingLabel, ssM, ssX, ctX, pkX), [.. ctM, .. ctX]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
        }
    }

    public static byte[] Decapsulate(byte[] enc, byte[] seed)
    {
        if (enc.Length != EncSize)
            throw new ArgumentException($"enc must be {EncSize} bytes, got {enc.Length}");

        var (mlKemPrivate, seedPq, x25519Private, pkX) = ExpandSeed(seed);

        var ctM = enc[..MlKemCiphertextSize];
        var ctX = enc[MlKemCiphertextSize..];

        var ssM = new byte[SharedSecretSize];
        var ssX = new byte[SharedSecretSize];

        try
        {
            var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            decapsulator.Init(mlKemPrivate);
            decapsulator.Decapsulate(ctM, 0, MlKemCiphertextSize, ssM, 0, SharedSecretSize);

            // X25519 DH — the low-order guard and all-zero check live in the helper.
            CryptoHelper.X25519Agree(x25519Private, new X25519PublicKeyParameters(ctX), ssX);

            return HybridKem.CombineSharedSecrets(XWingLabel, ssM, ssX, ctX, pkX);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
            CryptographicOperations.ZeroMemory(seedPq);
        }
    }

    private static (MLKemPrivateKeyParameters mlKemPrivate, byte[] seedPQ, X25519PrivateKeyParameters x25519Private, byte[] pkX) ExpandSeed(byte[] seed)
    {
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(seed, 0, X25519KeySize);

        var seedPq = new byte[MlKemSeedSize];
        shake.Output(seedPq, 0, MlKemSeedSize);

        var seedT = new byte[X25519KeySize];
        shake.Output(seedT, 0, X25519KeySize);

        try
        {
            var mlKemPrivate = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seedPq);
            var x25519Private = new X25519PrivateKeyParameters(seedT);
            var pkX = x25519Private.GeneratePublicKey().GetEncoded();

            // seedPq is handed back so callers can clear it once they are done with the derived
            // private key; seedT has already been copied into x25519Private and is cleared here.
            return (mlKemPrivate, seedPq, x25519Private, pkX);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seedT);
        }
    }
}