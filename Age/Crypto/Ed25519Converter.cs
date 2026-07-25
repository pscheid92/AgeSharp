using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace AgeSharp.Crypto;

internal static class Ed25519Converter
{
    // Ed25519 and X25519 use the same curve in different coordinates; age reuses an SSH key by
    // converting it rather than requiring a separate one.
    public static byte[] PublicKeyToX25519(byte[] ed25519PublicKey)
    {
        if (ed25519PublicKey.Length != 32)
            throw new ArgumentException("Ed25519 public key must be 32 bytes");

        // The high bit of the last byte is the sign bit in Ed25519; clear it to get y
        var yBytes = new byte[32];
        Array.Copy(ed25519PublicKey, yBytes, 32);
        yBytes[31] &= 0x7F;

        // Decode y into field element limbs
        var y = new int[X25519Field.Size];
        X25519Field.Decode(yBytes, 0, y);

        // u = (1 + y) / (1 - y) mod p
        var one = new int[X25519Field.Size];
        X25519Field.One(one);

        var numerator = new int[X25519Field.Size]; // 1 + y
        X25519Field.Add(one, y, numerator);

        var denominator = new int[X25519Field.Size]; // 1 - y
        X25519Field.Sub(one, y, denominator);

        var invDenom = new int[X25519Field.Size];
        X25519Field.Inv(denominator, invDenom);

        var u = new int[X25519Field.Size];
        X25519Field.Mul(numerator, invDenom, u);

        // Normalize and encode
        X25519Field.Normalize(u);
        var result = new byte[32];
        X25519Field.Encode(u, result, 0);
        return result;
    }

    public static byte[] PrivateKeyToX25519(byte[] ed25519Seed)
    {
        if (ed25519Seed.Length != 32)
            throw new ArgumentException("Ed25519 seed must be 32 bytes");

        var sha512 = new Sha512Digest();
        var hash = new byte[64];
        sha512.BlockUpdate(ed25519Seed, 0, ed25519Seed.Length);
        sha512.DoFinal(hash, 0);

        var result = new byte[32];
        Array.Copy(hash, result, 32);
        return result;
    }
}