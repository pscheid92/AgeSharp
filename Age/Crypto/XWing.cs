using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AgeSharp.Crypto;

internal static class XWing
{
    private const int MlKemPublicKeySize = 1184;
    private const int MlKemCiphertextSize = 1088;
    private const int X25519KeySize = 32;
    private const int SharedSecretSize = 32;
    private const int MlKemSeedSize = 64;

    internal const int PublicKeySize = MlKemPublicKeySize + X25519KeySize;

    internal const int EncSize = MlKemCiphertextSize + X25519KeySize;

    // X-Wing combiner label: ASCII `\.//^\` (the X-Wing spec domain separator)
    private static readonly byte[] XWingLabel = @"\.//^\"u8.ToArray();

    public static byte[] GeneratePublicKey(byte[] seed)
    {
        var (mlKemPrivate, _, x25519Private, _) = ExpandSeed(seed);

        var pkM = mlKemPrivate.GetPublicKeyEncoded(); // 1184 bytes (see MlKemPublicKeySize)
        var pkX = x25519Private.GeneratePublicKey().GetEncoded(); // 32 bytes (see X25519KeySize) 

        var publicKey = new byte[PublicKeySize];
        pkM.CopyTo(publicKey, 0);
        pkX.CopyTo(publicKey, MlKemPublicKeySize);
        return publicKey;
    }

    public static (byte[] SharedSecret, byte[] Enc) Encaps(byte[] publicKey)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        var pkM = publicKey[..MlKemPublicKeySize];
        var pkX = publicKey[MlKemPublicKeySize..];

        // ML-KEM-768 encapsulate
        var mlKemPub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, pkM);
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(mlKemPub);
        var ctM = new byte[MlKemCiphertextSize];
        var ssM = new byte[SharedSecretSize];
        encapsulator.Encapsulate(ctM, 0, MlKemCiphertextSize, ssM, 0, SharedSecretSize);

        // X25519 ephemeral DH. pkX comes from a recipient string, so it can carry a
        // low-order point; the shared helper rejects the resulting all-zero secret
        // rather than letting a raw BouncyCastle exception escape.
        var ekX = new X25519PrivateKeyParameters(new SecureRandom());
        var ctX = ekX.GeneratePublicKey().GetEncoded();
        var ssX = CryptoHelper.X25519Agree(ekX, new X25519PublicKeyParameters(pkX));

        // Combine: enc = ct_M || ct_X
        var enc = new byte[EncSize];
        ctM.CopyTo(enc, 0);
        ctX.CopyTo(enc, MlKemCiphertextSize);

        // ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
        var sharedSecret = CombineSharedSecret(ssM, ssX, ctX, pkX);

        return (sharedSecret, enc);
    }

    public static byte[] Decaps(byte[] enc, byte[] seed)
    {
        if (enc.Length != EncSize)
            throw new ArgumentException($"enc must be {EncSize} bytes, got {enc.Length}");

        var (mlKemPrivate, _, x25519Private, pkX) = ExpandSeed(seed);

        var ctM = enc[..MlKemCiphertextSize];
        var ctX = enc[MlKemCiphertextSize..];

        // ML-KEM-768 decapsulate
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(mlKemPrivate);
        var ssM = new byte[SharedSecretSize];
        decapsulator.Decapsulate(ctM, 0, MlKemCiphertextSize, ssM, 0, SharedSecretSize);

        // X25519 DH — the all-zero rejection lives in the shared helper.
        var ssX = CryptoHelper.X25519Agree(x25519Private, new X25519PublicKeyParameters(ctX));

        // ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
        return CombineSharedSecret(ssM, ssX, ctX, pkX);
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

    private static (MLKemPrivateKeyParameters mlKemPrivate, byte[] seedPQ, X25519PrivateKeyParameters x25519Private,
        byte[] pkX) ExpandSeed(byte[] seed)
    {
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(seed, 0, X25519KeySize);

        var seedPq = new byte[MlKemSeedSize];
        shake.Output(seedPq, 0, MlKemSeedSize);

        var seedT = new byte[X25519KeySize];
        shake.Output(seedT, 0, X25519KeySize);

        var mlKemPrivate = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seedPq);
        var x25519Private = new X25519PrivateKeyParameters(seedT);
        var pkX = x25519Private.GeneratePublicKey().GetEncoded();

        return (mlKemPrivate, seedPq, x25519Private, pkX);
    }
}