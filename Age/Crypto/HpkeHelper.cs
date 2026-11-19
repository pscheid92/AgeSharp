using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Crypto;

/// <summary>
/// HPKE (RFC 9180) in base mode, single-shot, with HKDF-SHA256 and ChaCha20-Poly1305: the KDF
/// and AEAD every age recipient type built on HPKE uses. The KEM is the caller's; it is named
/// by its ID, which goes into the key schedule's suite ID.
/// </summary>
/// <remarks>
/// Compared with filippo.io/hpke v0.4.0 (hpke.go, kdf.go), which go-age uses, and checked
/// against the RFC 9180 test vectors.
/// </remarks>
internal static class HpkeHelper
{
    private const ushort HkdfSha256 = 0x0001;
    private const ushort ChaCha20Poly1305 = 0x0003;

    private const int KeySize = 32;
    private const int NonceSize = 12;

    private static readonly byte[] HpkeV1 = "HPKE-v1"u8.ToArray();

    /// <summary>
    /// Seals <paramref name="plaintext"/> as the first message of a sender context set up from
    /// the KEM's shared secret.
    /// </summary>
    public static byte[] SealBase(ushort kemId, byte[] sharedSecret, byte[] info, byte[] plaintext)
    {
        var (key, nonce) = KeyScheduleBase(kemId, sharedSecret, info);

        try
        {
            return CryptoHelper.ChaChaEncrypt(key, nonce, plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>Opens the first message of a recipient context, or returns null if it does not authenticate.</summary>
    public static byte[]? OpenBase(ushort kemId, byte[] sharedSecret, byte[] info, byte[] ciphertext)
    {
        var (key, nonce) = KeyScheduleBase(kemId, sharedSecret, info);

        try
        {
            return CryptoHelper.ChaChaDecrypt(key, nonce, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>The key schedule of RFC 9180, section 5.1, in base mode: the AEAD key and base nonce.</summary>
    internal static (byte[] Key, byte[] Nonce) KeyScheduleBase(ushort kemId, byte[] sharedSecret, byte[] info)
    {
        var suiteId = SuiteId(kemId);
        var empty = Array.Empty<byte>();

        var pskIdHash = LabeledExtract(suiteId, empty, "psk_id_hash", empty);
        var infoHash = LabeledExtract(suiteId, empty, "info_hash", info);

        // ks_context = 0x00 || psk_id_hash || info_hash
        var ksContext = new byte[1 + 32 + 32];
        ksContext[0] = 0x00;
        pskIdHash.CopyTo(ksContext, 1);
        infoHash.CopyTo(ksContext, 33);

        // secret is the HPKE PRK — both the key and the nonce derive from it, so it outlives
        // neither and is cleared as soon as they exist.
        var secret = LabeledExtract(suiteId, sharedSecret, "secret", empty);

        try
        {
            return (LabeledExpand(suiteId, secret, "key", ksContext, KeySize),
                    LabeledExpand(suiteId, secret, "base_nonce", ksContext, NonceSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    // suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
    private static byte[] SuiteId(ushort kemId) =>
    [
        (byte)'H', (byte)'P', (byte)'K', (byte)'E',
        (byte)(kemId >> 8), (byte)kemId,
        HkdfSha256 >> 8, HkdfSha256 & 0xff,
        ChaCha20Poly1305 >> 8, ChaCha20Poly1305 & 0xff,
    ];

    /// <summary>
    /// LabeledExtract of RFC 9180, section 4, over HKDF-SHA256. <paramref name="suiteId"/> is
    /// either the HPKE suite ID or a KEM's own ("KEM" || kem_id), which DHKEM's
    /// ExtractAndExpand uses.
    /// </summary>
    internal static byte[] LabeledExtract(byte[] suiteId, byte[] salt, string label, byte[] ikm)
    {
        // labeled_ikm = "HPKE-v1" || suite_id || label || ikm
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var labeledIkm = new byte[HpkeV1.Length + suiteId.Length + labelBytes.Length + ikm.Length];

        var pos = 0;
        HpkeV1.CopyTo(labeledIkm, pos);
        pos += HpkeV1.Length;

        suiteId.CopyTo(labeledIkm, pos);
        pos += suiteId.Length;

        labelBytes.CopyTo(labeledIkm, pos);
        pos += labelBytes.Length;

        ikm.CopyTo(labeledIkm, pos);

        // actual_salt: if empty, use Nh zero bytes (32 for SHA-256)
        var actualSalt = salt.Length > 0 ? salt : new byte[32];

        try
        {
            return CryptoHelper.HmacSha256(actualSalt, labeledIkm);
        }
        finally
        {
            // labeledIkm ends with a verbatim copy of ikm, which on the "secret" and "eae_prk"
            // calls is key material.
            CryptographicOperations.ZeroMemory(labeledIkm);
        }
    }

    /// <summary>LabeledExpand of RFC 9180, section 4, over HKDF-SHA256.</summary>
    internal static byte[] LabeledExpand(byte[] suiteId, byte[] prk, string label, byte[] info, int length)
    {
        // labeled_info = I2OSP(length, 2) || "HPKE-v1" || suite_id || label || info
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var labeledInfo = new byte[2 + HpkeV1.Length + suiteId.Length + labelBytes.Length + info.Length];

        var pos = 0;
        labeledInfo[pos++] = (byte)(length >> 8);
        labeledInfo[pos++] = (byte)(length & 0xff);
        HpkeV1.CopyTo(labeledInfo, pos);

        pos += HpkeV1.Length;
        suiteId.CopyTo(labeledInfo, pos);

        pos += suiteId.Length;
        labelBytes.CopyTo(labeledInfo, pos);

        pos += labelBytes.Length;
        info.CopyTo(labeledInfo, pos);

        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(HkdfParameters.SkipExtractParameters(prk, labeledInfo));
        var result = new byte[length];
        hkdf.GenerateBytes(result, 0, length);
        return result;
    }
}
