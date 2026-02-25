using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Age.Crypto;

internal static class CryptoHelper
{
    private const int ChaChaMacSizeBits = 128;

    public static byte[] HkdfDerive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        var result = new byte[length];

        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm.ToArray(), salt.ToArray(), Encoding.ASCII.GetBytes(info)));
        hkdf.GenerateBytes(result, 0, length);

        return result;
    }

    public static byte[] ChaChaEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var cipher = new ChaCha20Poly1305();

        var parameters = new AeadParameters(new KeyParameter(key.ToArray()), ChaChaMacSizeBits, nonce.ToArray());
        cipher.Init(true, parameters);

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, output, 0);

        cipher.DoFinal(output, len);
        return output;
    }

    public static byte[]? ChaChaDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext)
    {
        var cipher = new ChaCha20Poly1305();

        var parameters = new AeadParameters(new KeyParameter(key.ToArray()), ChaChaMacSizeBits, nonce.ToArray());
        cipher.Init(false, parameters);

        var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
        var len = cipher.ProcessBytes(ciphertext.ToArray(), 0, ciphertext.Length, output, 0);

        try
        {
            cipher.DoFinal(output, len);
        }
        catch (InvalidCipherTextException)
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