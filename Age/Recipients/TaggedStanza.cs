using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;

namespace Age.Recipients;

/// <summary>
/// The stanza both tagged recipient types write: the file key sealed with HPKE, and a 4-byte
/// tag that lets hardware tell which stanza is its own before asking for user presence.
/// </summary>
/// <remarks>
/// As in age.md ("The tagged recipient types") and go-age's tag.Recipient.WrapWithLabels:
/// the arguments are the tag and enc, both base64, and the body is the HPKE ciphertext.
/// <code>tag = HKDF-Extract-SHA-256(ikm = enc || SHA-256(tagged key)[:4], salt = info)[:4]</code>
/// The tagged key is the recipient's P-256 point: compressed for p256tag, and for
/// mlkem768p256tag the uncompressed point alone, without the ML-KEM key.
/// </remarks>
internal static class TaggedStanza
{
    private const int TagSize = 4;

    public static Stanza Wrap(string stanzaType, ushort kemId, byte[] info,
        (byte[] SharedSecret, byte[] Enc) encapsulation, ReadOnlySpan<byte> taggedKey, ReadOnlySpan<byte> fileKey)
    {
        var (sharedSecret, enc) = encapsulation;

        // Named rather than inlined: an argument's ToArray() would leave a copy of the file key
        // with nothing to clear it by.
        var fileKeyCopy = fileKey.ToArray();

        try
        {
            var body = HpkeHelper.SealBase(kemId, sharedSecret, info, fileKeyCopy);
            return new Stanza(stanzaType, [Base64Unpadded.Encode(Tag(enc, taggedKey, info)), Base64Unpadded.Encode(enc)], body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKeyCopy);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    private static byte[] Tag(byte[] enc, ReadOnlySpan<byte> taggedKey, byte[] info)
    {
        // HKDF-Extract(salt, ikm) is HMAC-SHA256 keyed with the salt — the same helper as the
        // rest of the library, which also runs in the browser.
        byte[] ikm = [.. enc, .. SHA256.HashData(taggedKey)[..TagSize]];
        return CryptoHelper.HmacSha256(info, ikm)[..TagSize];
    }
}
