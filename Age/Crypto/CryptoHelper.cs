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

    /// <summary>
    ///     Computes an X25519 shared secret — the single agreement path, used by every
    ///     caller so the all-zero rule is stated once. A low-order or identity public
    ///     point yields an all-zero shared secret, which the age spec says the
    ///     implementation MUST reject.
    /// </summary>
    /// <remarks>
    ///     BouncyCastle rejects that case itself by throwing
    ///     <see cref="InvalidOperationException" />, normalized here into an
    ///     <see cref="AgeFormatException" /> so a crafted stanza can't leak a raw BCL
    ///     exception through decryption. The explicit all-zero check that follows is
    ///     belt-and-suspenders: the spec's requirement is on us, not on the backend, and
    ///     this way it does not silently lapse if a future BouncyCastle — or a different
    ///     backend — returns the zero secret instead of throwing. The caller owns the
    ///     returned secret and must zero it after use.
    /// </remarks>
    public static byte[] X25519Agree(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey)
    {
        var agreement = new X25519Agreement();
        agreement.Init(privateKey);
        var sharedSecret = new byte[agreement.AgreementSize];

        try
        {
            agreement.CalculateAgreement(publicKey, sharedSecret, 0);
        }
        catch (InvalidOperationException)
        {
            throw new AgeFormatException("X25519 shared secret is all-zero (low-order or identity point)");
        }

        if (sharedSecret.All(b => b == 0))
            throw new AgeFormatException("X25519 shared secret is all-zero (low-order or identity point)");

        return sharedSecret;
    }

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