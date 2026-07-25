using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
///     <see cref="IAeadCipher" /> backed by the platform <see cref="ChaCha20Poly1305" /> —
///     native, hardware-optimized, and zero per-call allocation. Unavailable on browser/WASM
///     (the constructor throws there); callers select it only when
///     <see cref="ChaCha20Poly1305.IsSupported" /> is true.
/// </summary>
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