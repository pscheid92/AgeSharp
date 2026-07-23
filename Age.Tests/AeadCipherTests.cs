using System.Security.Cryptography;
using Age.Crypto;
using Xunit;

namespace Age.Tests;

public class AeadCipherTests
{
    // Empty final chunk, sub-block, ChaCha block boundary, and full age chunk size.
    private static readonly int[] Sizes = [0, 1, 63, 64, 65, 100, 65536];

    private const int TagSize = 16;

    // AeadBackend is internal, so tests parametrize by a public bool and map inside the body.
    private static IAeadCipher Create(bool portable, ReadOnlySpan<byte> key) =>
        AeadCipher.Create(key, portable ? AeadBackend.Portable : AeadBackend.Native);

    private static (byte[] key, byte[] nonce, byte[] plaintext) Material(int size)
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var plaintext = new byte[size];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(plaintext);
        return (key, nonce, plaintext);
    }

    [Theory]
    [InlineData(false)] // native
    [InlineData(true)]  // portable
    public void RoundTrip_AllSizes(bool portable)
    {
        foreach (var size in Sizes)
        {
            var (key, nonce, plaintext) = Material(size);
            var ciphertext = new byte[size];
            var tag = new byte[TagSize];

            using (var enc = Create(portable, key))
                enc.Encrypt(nonce, plaintext, ciphertext, tag);

            var decrypted = new byte[size];
            using (var dec = Create(portable, key))
                dec.Decrypt(nonce, ciphertext, tag, decrypted);

            Assert.Equal(plaintext, decrypted);
        }
    }

    // The highest-value test: the two backends must be wire-identical. If this passes, every
    // code path that works with the native cipher works with BouncyCastle. It also pins the
    // MAC-size-in-bits constant (a wrong value produces a different tag).
    [Fact]
    public void Backends_ProduceByteIdenticalOutput_AndCrossDecrypt()
    {
        foreach (var size in Sizes)
        {
            var (key, nonce, plaintext) = Material(size);

            var bclCt = new byte[size];
            var bclTag = new byte[TagSize];
            using (var bcl = new BclAeadCipher(key))
                bcl.Encrypt(nonce, plaintext, bclCt, bclTag);

            var bcCt = new byte[size];
            var bcTag = new byte[TagSize];
            using (var bc = new BouncyCastleAeadCipher(key))
                bc.Encrypt(nonce, plaintext, bcCt, bcTag);

            Assert.Equal(bclCt, bcCt);
            Assert.Equal(bclTag, bcTag);

            // Each backend decrypts the other's output.
            var viaBc = new byte[size];
            using (var bc = new BouncyCastleAeadCipher(key))
                bc.Decrypt(nonce, bclCt, bclTag, viaBc);
            Assert.Equal(plaintext, viaBc);

            var viaBcl = new byte[size];
            using (var bcl = new BclAeadCipher(key))
                bcl.Decrypt(nonce, bcCt, bcTag, viaBcl);
            Assert.Equal(plaintext, viaBcl);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TamperedTag_Throws(bool portable)
    {
        var (key, nonce, plaintext) = Material(100);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var enc = Create(portable, key))
            enc.Encrypt(nonce, plaintext, ciphertext, tag);

        tag[0] ^= 0xFF;

        using var dec = Create(portable, key);
        Assert.Throws<AuthenticationTagMismatchException>(
            () => dec.Decrypt(nonce, ciphertext, tag, new byte[plaintext.Length]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TamperedCiphertext_Throws(bool portable)
    {
        var (key, nonce, plaintext) = Material(100);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var enc = Create(portable, key))
            enc.Encrypt(nonce, plaintext, ciphertext, tag);

        ciphertext[0] ^= 0xFF;

        using var dec = Create(portable, key);
        Assert.Throws<AuthenticationTagMismatchException>(
            () => dec.Decrypt(nonce, ciphertext, tag, new byte[plaintext.Length]));
    }

    // Mirrors the streaming path: one cipher instance reused for many chunks with distinct nonces.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReuseAcrossChunks(bool portable)
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var enc = Create(portable, key);
        using var dec = Create(portable, key);

        for (var i = 0; i < 5; i++)
        {
            var nonce = new byte[12];
            nonce[0] = (byte)i;
            var plaintext = new byte[1000 + i];
            RandomNumberGenerator.Fill(plaintext);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];
            enc.Encrypt(nonce, plaintext, ciphertext, tag);

            var decrypted = new byte[plaintext.Length];
            dec.Decrypt(nonce, ciphertext, tag, decrypted);
            Assert.Equal(plaintext, decrypted);
        }
    }
}
