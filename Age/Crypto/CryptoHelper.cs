using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Crypto;

internal static class CryptoHelper
{
    private const int ChaChaTagSize = 16;
    private const int Sha256Size = 32;

    public static byte[] HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        // Delegated to BouncyCastle's HkdfBytesGenerator for RFC 5869
        // correctness across all platforms. .NET's HKDF.DeriveKey uses OpenSSL
        // on Linux, which rejects empty IKM — but the age spec uses empty
        // IKM for the SSH-Ed25519 tweak derivation. BouncyCastle handles
        // this uniformly. HKDF is called once per session, not per chunk,
        // so the ToArray() allocations here are not a hot path.
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm.ToArray(), salt.ToArray(), Encoding.ASCII.GetBytes(info)));
        var result = new byte[length];
        hkdf.GenerateBytes(result, 0, length);
        return result;
    }

    public static void ChaChaEncrypt(ChaCha20Poly1305 cipher, ReadOnlySpan<byte> nonce,
                                      ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        cipher.Encrypt(nonce, plaintext,
            ciphertextWithTag[..plaintext.Length],
            ciphertextWithTag.Slice(plaintext.Length, ChaChaTagSize));
    }

    public static void ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
                                      ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        using var cipher = new ChaCha20Poly1305(key);
        ChaChaEncrypt(cipher, nonce, plaintext, ciphertextWithTag);
    }

    public static byte[] ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + ChaChaTagSize];
        ChaChaEncrypt(key, nonce, plaintext, output);
        return output;
    }

    public static bool ChaChaDecrypt(ChaCha20Poly1305 cipher, ReadOnlySpan<byte> nonce,
                                      ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintext)
    {
        if (ciphertextWithTag.Length < ChaChaTagSize)
            return false;

        var plaintextLen = ciphertextWithTag.Length - ChaChaTagSize;

        try
        {
            cipher.Decrypt(nonce,
                ciphertextWithTag[..plaintextLen],
                ciphertextWithTag[plaintextLen..],
                plaintext[..plaintextLen]);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        return true;
    }

    public static bool ChaChaDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
                                      ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintext)
    {
        using var cipher = new ChaCha20Poly1305(key);
        return ChaChaDecrypt(cipher, nonce, ciphertextWithTag, plaintext);
    }

    public static byte[]? ChaChaDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < ChaChaTagSize)
            return null;

        var plaintext = new byte[ciphertext.Length - ChaChaTagSize];
        return ChaChaDecrypt(key, nonce, ciphertext, plaintext) ? plaintext : null;
    }

    public static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var result = new byte[Sha256Size];
        HMACSHA256.HashData(key, data, result);
        return result;
    }
}
