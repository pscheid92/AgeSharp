using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Crypto;

internal static class XWing
{
    // X-Wing label: ASCII art `\.//^\`
    private static readonly byte[] XWingLabel = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

    internal const int PublicKeySize = 1184 + 32;  // ML-KEM-768 pk + X25519 pk
    internal const int EncSize = 1088 + 32;        // ML-KEM-768 ct + X25519 ephemeral

    public static byte[] GeneratePublicKey(byte[] seed)
    {
        var (mlKemPriv, _, x25519Priv, _) = ExpandSeed(seed);

        var pkM = mlKemPriv.GetPublicKeyEncoded();  // 1184 bytes
        var pkX = x25519Priv.GeneratePublicKey().GetEncoded();  // 32 bytes

        var publicKey = new byte[PublicKeySize];
        pkM.CopyTo(publicKey, 0);
        pkX.CopyTo(publicKey, 1184);
        return publicKey;
    }

    public static (byte[] SharedSecret, byte[] Enc) Encaps(byte[] publicKey)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"public key must be {PublicKeySize} bytes, got {publicKey.Length}");

        var pkM = publicKey[..1184];
        var pkX = publicKey[1184..];

        // ML-KEM-768 encapsulate
        var mlKemPub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, pkM);
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(mlKemPub);
        var ctM = new byte[1088];
        var ssM = new byte[32];
        encapsulator.Encapsulate(ctM, 0, 1088, ssM, 0, 32);

        // X25519 ephemeral DH
        var ekX = new X25519PrivateKeyParameters(new SecureRandom());
        var ctX = ekX.GeneratePublicKey().GetEncoded();  // 32 bytes
        var ssX = new byte[32];
        var agreement = new X25519Agreement();
        agreement.Init(ekX);
        agreement.CalculateAgreement(new X25519PublicKeyParameters(pkX), ssX, 0);

        // Combine: enc = ct_M || ct_X
        var enc = new byte[EncSize];
        ctM.CopyTo(enc, 0);
        ctX.CopyTo(enc, 1088);

        // ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
        var sharedSecret = CombineSharedSecret(ssM, ssX, ctX, pkX);

        return (sharedSecret, enc);
    }

    public static byte[] Decaps(byte[] enc, byte[] seed)
    {
        if (enc.Length != EncSize)
            throw new ArgumentException($"enc must be {EncSize} bytes, got {enc.Length}");

        var (mlKemPriv, _, x25519Priv, pkX) = ExpandSeed(seed);

        var ctM = enc[..1088];
        var ctX = enc[1088..];

        // ML-KEM-768 decapsulate
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(mlKemPriv);
        var ssM = new byte[32];
        decapsulator.Decapsulate(ctM, 0, 1088, ssM, 0, 32);

        // X25519 DH
        var ssX = new byte[32];
        var agreement = new X25519Agreement();
        agreement.Init(x25519Priv);
        try
        {
            agreement.CalculateAgreement(new X25519PublicKeyParameters(ctX), ssX, 0);
        }
        catch (InvalidOperationException)
        {
            throw new AgeHeaderException("X-Wing X25519 agreement failed (low-order or identity point)");
        }

        // Check for all-zero shared secret (low-order point that BC didn't reject)
        if (ssX.All(b => b == 0))
            throw new AgeHeaderException("X-Wing X25519 shared secret is all-zero (low-order or identity point)");

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
        var result = new byte[32];
        sha3.DoFinal(result, 0);
        return result;
    }

    private static (MLKemPrivateKeyParameters mlKemPriv, byte[] seedPQ, X25519PrivateKeyParameters x25519Priv, byte[] pkX) ExpandSeed(byte[] seed)
    {
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(seed, 0, 32);

        var seedPQ = new byte[64];
        shake.Output(seedPQ, 0, 64);

        var seedT = new byte[32];
        shake.Output(seedT, 0, 32);

        var mlKemPriv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seedPQ);
        var x25519Priv = new X25519PrivateKeyParameters(seedT);
        var pkX = x25519Priv.GeneratePublicKey().GetEncoded();

        return (mlKemPriv, seedPQ, x25519Priv, pkX);
    }
}
