using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Crypto;

internal static class CryptoHelper
{
    private const int ChaChaTagSize = 16;
    private const int Sha256Size = 32;

    /// <summary>Size of an X25519 shared secret, and so of the buffer <see cref="X25519Agree" /> fills.</summary>
    public const int X25519SharedSecretSize = 32;

    /// <summary>
    ///     The one place an X25519 agreement is performed. The spec requires rejecting an
    ///     all-zero shared secret, and BouncyCastle already refuses low-order and identity points
    ///     — but it does so with a raw <see cref="InvalidOperationException" />, which escaped
    ///     five of the eight call sites and surfaced from public Encrypt/Decrypt as an unhandled
    ///     BCL exception. main's own CLI reported a merely-malformed input file as a library bug.
    /// </summary>
    /// <remarks>
    ///     This is defence in depth plus a consistent exception type, not the closing of an
    ///     exploitable hole: no zero shared secret was ever used, because the agreement itself
    ///     fails first.
    /// </remarks>
    public static void X25519Agree(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey,
        Span<byte> sharedSecret)
    {
        var agreement = new X25519Agreement();
        agreement.Init(privateKey);

        // BouncyCastle writes into an array, so one transient heap copy is unavoidable here.
        var buffer = new byte[agreement.AgreementSize];

        try
        {
            try
            {
                agreement.CalculateAgreement(publicKey, buffer, 0);
            }
            catch (InvalidOperationException ex)
            {
                throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)", ex);
            }

            if (buffer.All(b => b == 0))
                throw new AgeHeaderException("X25519 shared secret is all-zero (low-order or identity point)");

            buffer.CopyTo(sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static byte[] HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        // BouncyCastle rather than HKDF.DeriveKey: the latter uses OpenSSL on Linux, which
        // rejects the empty IKM the spec's SSH-Ed25519 tweak derivation needs. The copy
        // BouncyCastle requires is key material, so it is cleared rather than left to the GC.
        var ikmCopy = ikm.ToArray();

        try
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(ikmCopy, salt.ToArray(), Encoding.ASCII.GetBytes(info)));
            var result = new byte[length];
            hkdf.GenerateBytes(result, 0, length);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikmCopy);
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
