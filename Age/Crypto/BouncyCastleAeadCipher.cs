using System.Buffers;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace AgeSharp.Crypto;

// Fallback for runtimes without a platform ChaCha20-Poly1305 (browser/WASM).
internal sealed class BouncyCastleAeadCipher : IAeadCipher
{
    private const int TagSize = 16;
    private const int MacSizeBits = TagSize * 8; // BouncyCastle expects the MAC size in BITS (128), not bytes

    private readonly BcChaCha20Poly1305 _cipher = new();
    private readonly KeyParameter _key;

    public BouncyCastleAeadCipher(ReadOnlySpan<byte> key)
    {
        _key = new KeyParameter(key.ToArray());
    }

    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
    {
        _cipher.Init(true, new AeadParameters(_key, MacSizeBits, nonce.ToArray()));

        // BouncyCastle emits ciphertext||tag contiguously; use a rented scratch and split.
        var scratch = ArrayPool<byte>.Shared.Rent(plaintext.Length + TagSize);
        try
        {
            var written = _cipher.ProcessBytes(plaintext, scratch);
            written += _cipher.DoFinal(scratch.AsSpan(written));
            scratch.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            scratch.AsSpan(plaintext.Length, TagSize).CopyTo(tag);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(scratch, true);
        }
    }

    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        _cipher.Init(false, new AeadParameters(_key, MacSizeBits, nonce.ToArray()));

        // BouncyCastle expects ciphertext||tag contiguously as input.
        var input = ArrayPool<byte>.Shared.Rent(ciphertext.Length + TagSize);
        var output = ArrayPool<byte>.Shared.Rent(ciphertext.Length);
        try
        {
            ciphertext.CopyTo(input);
            tag.CopyTo(input.AsSpan(ciphertext.Length));

            var written = _cipher.ProcessBytes(input.AsSpan(0, ciphertext.Length + TagSize), output);
            written += _cipher.DoFinal(output.AsSpan(written)); // throws InvalidCipherTextException on tag mismatch
            output.AsSpan(0, plaintext.Length).CopyTo(plaintext);
        }
        catch (InvalidCipherTextException)
        {
            // Translate to the BCL contract so CryptoHelper's existing catch continues to work.
            // Kept local to this method so it never intercepts BouncyCastle's RSA-OAEP failures.
            throw new AuthenticationTagMismatchException();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input, true);
            ArrayPool<byte>.Shared.Return(output, true);
        }
    }

    public void Dispose()
    {
        // No native/unmanaged state to release. The KeyParameter key copy cannot be zeroed (see remarks).
    }
}