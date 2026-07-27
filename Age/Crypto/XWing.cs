using Org.BouncyCastle.Crypto.Agreement;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Crypto;

internal static class XWing
{
    // X-Wing combiner label: ASCII `\.//^\` (the X-Wing spec domain separator)
    private static readonly byte[] XWingLabel = @"\.//^\"u8.ToArray();

    private const int MlKemPublicKeySize = 1184;
    private const int MlKemCiphertextSize = 1088;
    private const int X25519KeySize = 32;
    private const int SharedSecretSize = 32;
    private const int MlKemSeedSize = 64;

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
            // seedPq is the ML-KEM-768 private seed (d,z). Both call sites used to discard it
            // with `_`, leaving it on the heap with no reference left to clear it by.
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

        try
        {
            MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, publicKey[..MlKemPublicKeySize]);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw new FormatException($"invalid ML-KEM-768 encapsulation key: {ex.Message}", ex);
        }

        // FromEncoding does not check the coefficients — BouncyCastle defers that to Encapsulate,
        // far too late for a parse. FIPS 203's ByteDecode_12 requires every coefficient below q.
        if (!CoefficientsAreInRange(publicKey.AsSpan(0, CoefficientBytes)))
            throw new FormatException(
                "invalid ML-KEM-768 encapsulation key: a coefficient is not less than the modulus");
    }

    // The encapsulation key is k polynomials of 256 coefficients packed at 12 bits each, followed
    // by a 32-byte seed. Three bytes carry two coefficients.
    private const int CoefficientBytes = 1152;
    private const int Modulus = 3329;

    private static bool CoefficientsAreInRange(ReadOnlySpan<byte> packed)
    {
        for (var i = 0; i + 2 < packed.Length; i += 3)
        {
            var low = packed[i] | ((packed[i + 1] & 0x0F) << 8);
            var high = (packed[i + 1] >> 4) | (packed[i + 2] << 4);

            if (low >= Modulus || high >= Modulus)
                return false;
        }

        return true;
    }

    public static (byte[] SharedSecret, byte[] Enc) Encaps(byte[] publicKey)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        var pkM = publicKey[..MlKemPublicKeySize];
        var pkX = publicKey[MlKemPublicKeySize..];

        // ML-KEM-768 encapsulate
        MLKemPublicKeyParameters mlKemPub;

        try
        {
            mlKemPub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, pkM);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw new AgeHeaderException($"invalid ML-KEM-768 public key: {ex.Message}", ex);
        }

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(mlKemPub);
        var ctM = new byte[MlKemCiphertextSize];

        // Encaps is internal and callable without going through Parse, so it repeats the
        // coefficient check rather than trusting the caller.
        if (!CoefficientsAreInRange(pkM.AsSpan(0, CoefficientBytes)))
            throw new AgeHeaderException(
                "invalid ML-KEM-768 public key: a coefficient is not less than the modulus");

        // ssM and ssX are the two halves the combiner hashes; both are key material.
        var ssM = new byte[SharedSecretSize];
        encapsulator.Encapsulate(ctM, 0, MlKemCiphertextSize, ssM, 0, SharedSecretSize);

        // X25519 ephemeral DH. Decaps guarded this and Encaps did not — the asymmetry sat inside
        // one file. Both now go through the single guarded helper.
        var ekX = new X25519PrivateKeyParameters(new SecureRandom());
        var ctX = ekX.GeneratePublicKey().GetEncoded();
        var ssX = new byte[SharedSecretSize];

        try
        {
            CryptoHelper.X25519Agree(ekX, new X25519PublicKeyParameters(pkX), ssX);

            // Combine: enc = ct_M || ct_X
            var enc = new byte[EncSize];
            ctM.CopyTo(enc, 0);
            ctX.CopyTo(enc, MlKemCiphertextSize);

            // ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
            return (CombineSharedSecret(ssM, ssX, ctX, pkX), enc);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
        }
    }

    public static byte[] Decaps(byte[] enc, byte[] seed)
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
            // ML-KEM-768 decapsulate
            var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            decapsulator.Init(mlKemPrivate);
            decapsulator.Decapsulate(ctM, 0, MlKemCiphertextSize, ssM, 0, SharedSecretSize);

            // X25519 DH — the guard and the all-zero check both live in the helper now.
            CryptoHelper.X25519Agree(x25519Private, new X25519PublicKeyParameters(ctX), ssX);

            // ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
            return CombineSharedSecret(ssM, ssX, ctX, pkX);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
            CryptographicOperations.ZeroMemory(ssX);
            CryptographicOperations.ZeroMemory(seedPq);
        }
    }

    private static byte[] CombineSharedSecret(byte[] ssM, byte[] ssX, byte[] ctX, byte[] pkX)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(ssM, 0, ssM.Length);
        sha3.BlockUpdate(ssX, 0, ssX.Length);
        sha3.BlockUpdate(ctX, 0, ctX.Length);
        sha3.BlockUpdate(pkX, 0, pkX.Length);
        sha3.BlockUpdate(XWingLabel, 0, XWingLabel.Length);

        var result = new byte[SharedSecretSize];
        sha3.DoFinal(result, 0);
        return result;
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