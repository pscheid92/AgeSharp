using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The library never disposes a stream the caller supplied — it disposes only what it created
/// itself. That rule used to hold for binary input and break for armored input, because the
/// dearmor wrapper chain cascaded <see cref="Stream.Dispose()"/> all the way down to the caller's
/// ciphertext stream. Every entry point that can take armored input is covered here in both
/// shapes, so the two can never drift apart again.
/// </summary>
public class StreamOwnershipTests
{
    /// <summary>A stream that records whether anyone disposed it.</summary>
    private sealed class Tracked(byte[] data) : MemoryStream(data, writable: false)
    {
        public bool Disposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                Disposed = true;

            base.Dispose(disposing);
        }
    }

    private static (X25519Identity Identity, byte[] Ciphertext) Encrypt(bool armored, int size = 100)
    {
        var identity = X25519Identity.Generate();
        var plaintext = new byte[size];
        new Random(7).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, armored, identity.Recipient);

        return (identity, output.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Decrypt_Does_Not_Dispose_The_Caller_Stream(bool armored)
    {
        var (identity, ciphertext) = Encrypt(armored);
        using var _ = identity;

        var input = new Tracked(ciphertext);
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(input, output, identity);

        Assert.False(input.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DecryptReader_Does_Not_Dispose_The_Caller_Stream(bool armored)
    {
        var (identity, ciphertext) = Encrypt(armored);
        using var _ = identity;

        var input = new Tracked(ciphertext);
        using (var reader = AgeEncrypt.DecryptReader(input, identity))
            reader.CopyTo(Stream.Null);

        Assert.False(input.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void HeaderParse_Does_Not_Dispose_The_Caller_Stream(bool armored)
    {
        var (identity, ciphertext) = Encrypt(armored);
        using var _ = identity;

        var input = new Tracked(ciphertext);
        AgeHeader.Parse(input);

        Assert.False(input.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RandomAccess_Does_Not_Dispose_The_Caller_Stream(bool armored)
    {
        var (identity, ciphertext) = Encrypt(armored);
        using var _ = identity;

        var input = new Tracked(ciphertext);
        using (var random = new AgeRandomAccess(input, identity))
            Assert.Equal(100, random.PlaintextLength);

        Assert.False(input.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Encrypt_Does_Not_Dispose_The_Caller_Streams(bool armored)
    {
        using var identity = X25519Identity.Generate();
        var input = new Tracked(new byte[100]);
        using var output = new MemoryStream();

        AgeEncrypt.Encrypt(input, output, armored, identity.Recipient);

        Assert.False(input.Disposed);
        Assert.True(output.CanWrite); // still usable, i.e. not disposed
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptReader_Does_Not_Dispose_The_Caller_Stream(bool armored)
    {
        using var identity = X25519Identity.Generate();
        var input = new Tracked(new byte[100]);

        using (var reader = AgeEncrypt.EncryptReader(input, armored, identity.Recipient))
            reader.CopyTo(Stream.Null);

        Assert.False(input.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void The_Same_Stream_Can_Be_Decrypted_Twice(bool armored)
    {
        // The user-visible consequence of the old behaviour: a second decrypt of the same
        // armored stream threw ObjectDisposedException, while the binary case worked.
        var (identity, ciphertext) = Encrypt(armored);
        using var _ = identity;

        using var input = new MemoryStream(ciphertext);
        using var first = new MemoryStream();
        AgeEncrypt.Decrypt(input, first, identity);

        input.Position = 0;
        using var second = new MemoryStream();
        AgeEncrypt.Decrypt(input, second, identity);

        Assert.Equal(first.ToArray(), second.ToArray());
    }
}
