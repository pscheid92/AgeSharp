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

    public static byte[] ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + ChaChaTagSize];
        using var cipher = new ChaCha20Poly1305(key);
        cipher.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length, ChaChaTagSize));
        return output;
    }

    public static byte[]? ChaChaDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < ChaChaTagSize)
            return null;

        var plaintextLen = ciphertext.Length - ChaChaTagSize;
        var plaintext = new byte[plaintextLen];
        using var cipher = new ChaCha20Poly1305(key);

        try
        {
            cipher.Decrypt(nonce, ciphertext[..plaintextLen], ciphertext[plaintextLen..], plaintext);
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }

        return plaintext;
    }

    public static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var result = new byte[Sha256Size];
        HMACSHA256.HashData(key, data, result);
        return result;
    }
}
