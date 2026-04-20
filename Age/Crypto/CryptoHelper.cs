using System.Security.Cryptography;
using System.Text;

namespace Age.Crypto;

internal static class CryptoHelper
{
    private const int ChaChaTagSize = 16;
    private const int Sha256Size = 32;

    public static byte[] HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        var result = new byte[length];
        var infoByteCount = Encoding.ASCII.GetByteCount(info);
        Span<byte> infoBytes = stackalloc byte[infoByteCount];
        Encoding.ASCII.GetBytes(info, infoBytes);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, result, salt, infoBytes);
        return result;
    }

    public static void ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
                                      ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        using var cipher = new ChaCha20Poly1305(key);
        cipher.Encrypt(nonce, plaintext,
            ciphertextWithTag[..plaintext.Length],
            ciphertextWithTag.Slice(plaintext.Length, ChaChaTagSize));
    }

    public static byte[] ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + ChaChaTagSize];
        ChaChaEncrypt(key, nonce, plaintext, output);
        return output;
    }

    public static bool ChaChaDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
                                      ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintext)
    {
        if (ciphertextWithTag.Length < ChaChaTagSize)
            return false;

        var plaintextLen = ciphertextWithTag.Length - ChaChaTagSize;
        using var cipher = new ChaCha20Poly1305(key);

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
