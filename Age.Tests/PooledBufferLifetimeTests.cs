using System.Buffers;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// S4 / C12 — the payload streams rent from <see cref="ArrayPool{T}"/>, and
/// <see cref="Stream.Dispose()"/> carries no idempotence guard of its own. Calling
/// <c>Close()</c> and <c>Dispose()</c>, or nesting a <see cref="StreamReader"/> inside a
/// <c>using</c>, is ordinary caller code — and without a guard each pass returns the same
/// arrays again, so two later unrelated renters are handed one array.
/// </summary>
public class PooledBufferLifetimeTests
{
    private const int ChunkSize = 64 * 1024;

    private static (byte[] Ciphertext, X25519Identity Identity) Encrypted(int size = 4096)
    {
        var identity = X25519Identity.Generate();
        var plaintext = new byte[size];
        for (var i = 0; i < size; i++) plaintext[i] = (byte)(i * 31 % 251);

        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, identity.Recipient);

        return (output.ToArray(), identity);
    }

    // Rent two buffers and see whether the pool hands back the same array twice — the
    // observable signature of a double Return.
    private static bool PoolHandsOutTheSameArrayTwice()
    {
        var a = ArrayPool<byte>.Shared.Rent(ChunkSize);
        var b = ArrayPool<byte>.Shared.Rent(ChunkSize);
        var aliased = ReferenceEquals(a, b);

        ArrayPool<byte>.Shared.Return(a);
        if (!aliased) ArrayPool<byte>.Shared.Return(b);

        return aliased;
    }

    [Fact]
    public void DecryptReader_ClosedThenDisposed_DoesNotReturnPooledBuffersTwice()
    {
        var (ciphertext, identity) = Encrypted();
        using (identity)
        {
            var stream = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identity);
            using (var sink = new MemoryStream()) stream.CopyTo(sink);

            stream.Close();     // documented alias for Dispose()
            stream.Dispose();   // and disposing twice is legal
        }

        Assert.False(PoolHandsOutTheSameArrayTwice(),
            "ArrayPool handed the same array to two independent renters — a buffer was returned twice");
    }

    [Fact]
    public void EncryptReader_ClosedThenDisposed_DoesNotReturnPooledBuffersTwice()
    {
        using var identity = X25519Identity.Generate();

        var stream = AgeEncrypt.EncryptReader(new MemoryStream(new byte[4096]), identity.Recipient);
        using (var sink = new MemoryStream()) stream.CopyTo(sink);

        stream.Close();
        stream.Dispose();

        Assert.False(PoolHandsOutTheSameArrayTwice(),
            "ArrayPool handed the same array to two independent renters — a buffer was returned twice");
    }

    [Fact]
    public void ArmoredEncryptReader_ClosedThenDisposed_DoesNotReturnPooledBuffersTwice()
    {
        using var identity = X25519Identity.Generate();

        var stream = AgeEncrypt.EncryptReader(new MemoryStream(new byte[4096]), true, identity.Recipient);
        using (var sink = new MemoryStream()) stream.CopyTo(sink);

        stream.Close();
        stream.Dispose();

        Assert.False(PoolHandsOutTheSameArrayTwice(),
            "ArrayPool handed the same array to two independent renters — a buffer was returned twice");
    }

    // StreamReader.Dispose disposes the stream it wraps, so this idiomatic shape disposes twice
    // without the caller ever writing Dispose.
    [Fact]
    public void DecryptReader_WrappedInStreamReader_DoesNotReturnPooledBuffersTwice()
    {
        var (ciphertext, identity) = Encrypted();
        using (identity)
        {
            using (var stream = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identity))
            using (var reader = new StreamReader(stream))
                _ = reader.ReadToEnd();
        }

        Assert.False(PoolHandsOutTheSameArrayTwice(),
            "ArrayPool handed the same array to two independent renters — a buffer was returned twice");
    }

    [Fact]
    public void DecryptReader_ReadAfterDispose_Throws()
    {
        var (ciphertext, identity) = Encrypted();
        using (identity)
        {
            var stream = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identity);
            stream.Dispose();

            Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[16], 0, 16));
        }
    }

    [Fact]
    public void EncryptReader_ReadAfterDispose_Throws()
    {
        using var identity = X25519Identity.Generate();

        var stream = AgeEncrypt.EncryptReader(new MemoryStream(new byte[64]), identity.Recipient);
        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[16], 0, 16));
    }

    // A corrupted pool shows up as bogus authentication failures on files that are perfectly
    // well-formed, which is how this bug would actually be reported.
    [Fact]
    public void DoubleDispose_DoesNotCorruptLaterDecryptions()
    {
        var (ciphertext, identity) = Encrypted(200_000);
        using (identity)
        {
            var stream = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identity);
            using (var sink = new MemoryStream()) stream.CopyTo(sink);
            stream.Close();
            stream.Dispose();

            using var input = new MemoryStream(ciphertext);
            using var output = new MemoryStream();
            AgeEncrypt.Decrypt(input, output, identity);

            Assert.Equal(200_000, output.Length);
        }
    }
}
