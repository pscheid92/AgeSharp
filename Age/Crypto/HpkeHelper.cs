using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Crypto;

internal static class HpkeHelper
{
    // SuiteID = "HPKE" || BE16(0x647a) || BE16(0x0001) || BE16(0x0003)
    private static readonly byte[] SuiteId =
    {
        (byte)'H', (byte)'P', (byte)'K', (byte)'E',
        0x64, 0x7a,  // KEM ID: X-Wing
        0x00, 0x01,  // KDF ID: HKDF-SHA256
        0x00, 0x03   // AEAD ID: ChaCha20Poly1305
    };

    private static readonly byte[] HpkeV1 = Encoding.ASCII.GetBytes("HPKE-v1");

    public static (byte[] Enc, byte[] Ct) SealBase(byte[] publicKey, byte[] info, byte[] plaintext)
    {
        var (ss, enc) = XWing.Encaps(publicKey);
        var (key, nonce) = KeyScheduleBase(ss, info);
        var ct = CryptoHelper.ChaChaEncrypt(key, nonce, plaintext);
        return (enc, ct);
    }

    public static byte[]? OpenBase(byte[] enc, byte[] seed, byte[] info, byte[] ct)
    {
        var ss = XWing.Decaps(enc, seed);
        var (key, nonce) = KeyScheduleBase(ss, info);
        return CryptoHelper.ChaChaDecrypt(key, nonce, ct);
    }

    private static (byte[] Key, byte[] Nonce) KeyScheduleBase(byte[] sharedSecret, byte[] info)
    {
        var empty = Array.Empty<byte>();

        var pskIdHash = LabeledExtract(empty, "psk_id_hash", empty);
        var infoHash = LabeledExtract(empty, "info_hash", info);

        // ks_context = 0x00 || psk_id_hash || info_hash
        var ksContext = new byte[1 + 32 + 32];
        ksContext[0] = 0x00;
        pskIdHash.CopyTo(ksContext, 1);
        infoHash.CopyTo(ksContext, 33);

        var secret = LabeledExtract(sharedSecret, "secret", empty);

        var key = LabeledExpand(secret, "key", ksContext, 32);
        var baseNonce = LabeledExpand(secret, "base_nonce", ksContext, 12);

        return (key, baseNonce);
    }

    internal static byte[] LabeledExtract(byte[] salt, string label, byte[] ikm)
    {
        // labeled_ikm = "HPKE-v1" || SuiteID || label || ikm
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var labeledIkm = new byte[HpkeV1.Length + SuiteId.Length + labelBytes.Length + ikm.Length];
        int pos = 0;
        HpkeV1.CopyTo(labeledIkm, pos); pos += HpkeV1.Length;
        SuiteId.CopyTo(labeledIkm, pos); pos += SuiteId.Length;
        labelBytes.CopyTo(labeledIkm, pos); pos += labelBytes.Length;
        ikm.CopyTo(labeledIkm, pos);

        // actual_salt: if empty, use Nh zero bytes (32 for SHA-256)
        var actualSalt = salt.Length > 0 ? salt : new byte[32];

        // HKDF-Extract = HMAC(salt, ikm)
        return CryptoHelper.HmacSha256(actualSalt, labeledIkm);
    }

    internal static byte[] LabeledExpand(byte[] prk, string label, byte[] info, int length)
    {
        // labeled_info = BE16(length) || "HPKE-v1" || SuiteID || label || info
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var labeledInfo = new byte[2 + HpkeV1.Length + SuiteId.Length + labelBytes.Length + info.Length];
        int pos = 0;
        labeledInfo[pos++] = (byte)(length >> 8);
        labeledInfo[pos++] = (byte)(length & 0xff);
        HpkeV1.CopyTo(labeledInfo, pos); pos += HpkeV1.Length;
        SuiteId.CopyTo(labeledInfo, pos); pos += SuiteId.Length;
        labelBytes.CopyTo(labeledInfo, pos); pos += labelBytes.Length;
        info.CopyTo(labeledInfo, pos);

        // HKDF-Expand with PRK and labeled_info
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(HkdfParameters.SkipExtractParameters(prk, labeledInfo));
        var result = new byte[length];
        hkdf.GenerateBytes(result, 0, length);
        return result;
    }
}
