using Age;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class PullBasedTests
{
    [Fact]
    public void EncryptReader_Decrypt_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "pull-based encrypt test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        // Read all encrypted data
        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        // Decrypt with push-based API
        ciphertext.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(ciphertext, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Encrypt_DecryptReader_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "pull-based decrypt test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, identity.Recipient);

        ciphertext.Position = 0;
        using var decryptedStream = AgeEncrypt.DecryptReader(ciphertext, identity);

        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void BothPullBased_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "both pull-based"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        // Pipe encrypted reader into decrypt reader
        using var ciphertextBuffer = new MemoryStream();
        encryptedStream.CopyTo(ciphertextBuffer);
        ciphertextBuffer.Position = 0;

        using var decryptedStream = AgeEncrypt.DecryptReader(ciphertextBuffer, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void PartialReads_OneByteAtATime()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "byte by byte"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        // Read encrypted data one byte at a time
        using var ciphertext = new MemoryStream();
        var buf = new byte[1];
        int read;
        while ((read = encryptedStream.Read(buf, 0, 1)) > 0)
            ciphertext.Write(buf, 0, read);

        // Decrypt
        ciphertext.Position = 0;
        using var decryptedStream = AgeEncrypt.DecryptReader(ciphertext, identity);

        // Also read decrypted one byte at a time
        using var output = new MemoryStream();
        while ((read = decryptedStream.Read(buf, 0, 1)) > 0)
            output.Write(buf, 0, read);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void LargeFile_MultiChunk()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var decryptedStream = AgeEncrypt.DecryptReader(ciphertext, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void EmptyPlaintext()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Array.Empty<byte>();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var decryptedStream = AgeEncrypt.DecryptReader(ciphertext, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Armored_EncryptReader()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "armored pull test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, true, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(ciphertext, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void EncryptReader_CanSeekIsFalse()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream("test"u8.ToArray());
        using var stream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
    }

    [Fact]
    public void DecryptReader_CanSeekIsFalse()
    {
        using var identity = X25519Identity.Generate();

        using var input = new MemoryStream("test"u8.ToArray());
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, identity.Recipient);

        ciphertext.Position = 0;
        using var stream = AgeEncrypt.DecryptReader(ciphertext, identity);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
    }

    [Fact]
    public void ExactChunkSize()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[64 * 1024]; // Exactly one chunk
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = AgeEncrypt.EncryptReader(input, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var decryptedStream = AgeEncrypt.DecryptReader(ciphertext, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }
}
