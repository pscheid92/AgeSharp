using System.Security.Cryptography;

namespace AgeSharp.Crypto;

internal sealed class BclAeadCipher : IAeadCipher
{
    private readonly ChaCha20Poly1305 _cipher;

    public BclAeadCipher(ReadOnlySpan<byte> key)
    {
        _cipher = new ChaCha20Poly1305(key);
    }

    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        _cipher.Encrypt(nonce, plaintext, ciphertext, tag);
    }

    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        _cipher.Decrypt(nonce, ciphertext, tag, plaintext);
    }

    public void Dispose()
    {
        _cipher.Dispose();
    }
}