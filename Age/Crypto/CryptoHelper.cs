using System.Security.Cryptography;
using System.Text;

namespace Age.Crypto;

internal static class CryptoHelper
{
    private const int ChaChaTagSize = 16;
    private const int Sha256Size = 32;

    public static byte[] HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        // RFC 5869 HKDF-SHA256, implemented via HMACSHA256.HashData to work
        // uniformly across platforms. .NET's HKDF.DeriveKey dispatches to
        // OpenSSL on Linux, which rejects empty IKM — but the age spec uses
        // empty IKM for the SSH-Ed25519 tweak derivation.

        const int HashLen = 32;

        // Extract: PRK = HMAC-SHA256(salt, IKM). Empty salt → HashLen zeros.
        Span<byte> prk = stackalloc byte[HashLen];
        if (salt.IsEmpty)
        {
            Span<byte> zeroSalt = stackalloc byte[HashLen];
            HMACSHA256.HashData(zeroSalt, ikm, prk);
        }
        else
        {
            HMACSHA256.HashData(salt, ikm, prk);
        }

        // Expand: T(1) = HMAC(PRK, info || 0x01); T(i) = HMAC(PRK, T(i-1) || info || i); OKM = T(1) || T(2) || ...
        var infoByteCount = Encoding.ASCII.GetByteCount(info);
        Span<byte> infoBytes = stackalloc byte[infoByteCount];
        Encoding.ASCII.GetBytes(info, infoBytes);

        var result = new byte[length];
        Span<byte> tBlock = stackalloc byte[HashLen];
        Span<byte> inputBuffer = stackalloc byte[HashLen + infoByteCount + 1];
        var outputOffset = 0;
        byte counter = 1;

        while (outputOffset < length)
        {
            int inputLen;
            if (counter == 1)
            {
                infoBytes.CopyTo(inputBuffer);
                inputBuffer[infoByteCount] = counter;
                inputLen = infoByteCount + 1;
            }
            else
            {
                tBlock.CopyTo(inputBuffer);
                infoBytes.CopyTo(inputBuffer[HashLen..]);
                inputBuffer[HashLen + infoByteCount] = counter;
                inputLen = HashLen + infoByteCount + 1;
            }

            HMACSHA256.HashData(prk, inputBuffer[..inputLen], tBlock);

            var toCopy = Math.Min(HashLen, length - outputOffset);
            tBlock[..toCopy].CopyTo(result.AsSpan(outputOffset));

            outputOffset += toCopy;
            counter++;
        }

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
