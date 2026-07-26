using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace AgeSharp.Crypto;

internal static class CryptoHelper
{
    private const int ChaChaTagSize = 16;
    private const int Sha256Size = 32;

    public const int X25519SharedSecretSize = 32;

    // Fills rather than returns, so the secret can live on the caller's stack and never
    // reach the GC heap — where a compaction may leave a copy that zeroing the caller's
    // reference would not reach. The caller still clears its own buffer.
    //
    // The single X25519 agreement path: the spec's "MUST reject an all-zero shared secret"
    // is enforced here once.
    public static void X25519Agree(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey,
        Span<byte> sharedSecret)
    {
        var agreement = new X25519Agreement();
        agreement.Init(privateKey);

        // BouncyCastle writes into an array, so one transient copy is unavoidable here.
        var buffer = new byte[agreement.AgreementSize];

        try
        {
            try
            {
                agreement.CalculateAgreement(publicKey, buffer, 0);
            }
            catch (InvalidOperationException)
            {
                throw new AgeFormatException("X25519 shared secret is all-zero (low-order or identity point)");
            }

            if (buffer.All(b => b == 0))
                throw new AgeFormatException("X25519 shared secret is all-zero (low-order or identity point)");

            buffer.CopyTo(sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Fills <paramref name="output" /> with HKDF-SHA256 output. See X25519Agree on why this fills.</summary>
    public static void HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, Span<byte> output)
    {
        // .NET's HKDF rejects empty IKM on Linux (OpenSSL), which the ssh-ed25519 derivation
        // needs, so this goes through BouncyCastle — which takes arrays, hence the copies.
        var ikmCopy = ikm.ToArray();
        var buffer = new byte[output.Length];

        try
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(ikmCopy, salt.ToArray(), Encoding.ASCII.GetBytes(info)));
            hkdf.GenerateBytes(buffer, 0, buffer.Length);
            buffer.CopyTo(output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikmCopy);
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static void ChaChaEncrypt(IAeadCipher cipher, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        cipher.Encrypt(nonce, plaintext,
            ciphertextWithTag[..plaintext.Length],
            ciphertextWithTag.Slice(plaintext.Length, ChaChaTagSize));
    }

    public static void ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertextWithTag)
    {
        using var cipher = AeadCipher.Create(key);
        ChaChaEncrypt(cipher, nonce, plaintext, ciphertextWithTag);
    }

    public static byte[] ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + ChaChaTagSize];
        ChaChaEncrypt(key, nonce, plaintext, output);
        return output;
    }

    public static bool ChaChaDecrypt(IAeadCipher cipher, ReadOnlySpan<byte> nonce,
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
        using var cipher = AeadCipher.Create(key);
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