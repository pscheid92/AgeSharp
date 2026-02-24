using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Crypto;

internal static class CryptoHelper
{
    public static byte[] HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm.ToArray(), salt.ToArray(), System.Text.Encoding.ASCII.GetBytes(info)));
        var result = new byte[length];
        hkdf.GenerateBytes(result, 0, length);
        return result;
    }

    public static byte[] ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        cipher.Init(true, new AeadParameters(new KeyParameter(key.ToArray()), 128, nonce.ToArray()));

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, output, 0);
        cipher.DoFinal(output, len);
        return output;
    }

    public static byte[]? ChaChaDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext)
    {
        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        cipher.Init(false, new AeadParameters(new KeyParameter(key.ToArray()), 128, nonce.ToArray()));

        var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
        int len = cipher.ProcessBytes(ciphertext.ToArray(), 0, ciphertext.Length, output, 0);
        try
        {
            cipher.DoFinal(output, len);
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
        {
            return null;
        }
        return output;
    }

    public static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var hmac = new HMac(new Sha256Digest());
        hmac.Init(new KeyParameter(key.ToArray()));
        hmac.BlockUpdate(data.ToArray(), 0, data.Length);
        var result = new byte[hmac.GetMacSize()];
        hmac.DoFinal(result, 0);
        return result;
    }
}
