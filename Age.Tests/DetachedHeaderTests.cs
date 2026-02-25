using Age;
using Age.Format;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class DetachedHeaderTests
{
    [Fact]
    public void RoundTrip_EncryptDetached_DecryptDetached()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "Hello, detached!"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var headerOut = new MemoryStream();
        using var payloadOut = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, headerOut, payloadOut, identity.Recipient);

        headerOut.Position = 0;
        payloadOut.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.DecryptDetached(headerOut, payloadOut, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void CrossCompat_Encrypt_SplitAtOffset_DecryptDetached()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "cross-compat test"u8.ToArray();

        // Encrypt normally
        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, identity.Recipient);
        var ciphertextBytes = ciphertext.ToArray();

        // Parse header to find payload offset
        ciphertext.Position = 0;
        var header = AgeHeader.Parse(ciphertext);

        // Split at payload offset
        var headerBytes = ciphertextBytes[..(int)header.PayloadOffset];
        var payloadBytes = ciphertextBytes[(int)header.PayloadOffset..];

        using var headerIn = new MemoryStream(headerBytes);
        using var payloadIn = new MemoryStream(payloadBytes);
        using var output = new MemoryStream();
        AgeEncrypt.DecryptDetached(headerIn, payloadIn, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void CrossCompat_EncryptDetached_Concatenate_Decrypt()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "concatenate test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var headerOut = new MemoryStream();
        using var payloadOut = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, headerOut, payloadOut, identity.Recipient);

        // Concatenate header + payload into single stream
        using var combined = new MemoryStream();
        headerOut.Position = 0;
        headerOut.CopyTo(combined);
        payloadOut.Position = 0;
        payloadOut.CopyTo(combined);

        combined.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(combined, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void AgeHeader_Parse_Metadata()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();
        var plaintext = "metadata test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, id1.Recipient, id2.Recipient);

        ciphertext.Position = 0;
        var header = AgeHeader.Parse(ciphertext);

        Assert.Equal(2, header.RecipientCount);
        Assert.Equal(2, header.Recipients.Count);
        Assert.All(header.Recipients, s => Assert.Equal("X25519", s.Type));
        Assert.True(header.PayloadOffset > 0);
        Assert.False(header.IsArmored);
    }

    [Fact]
    public void AgeHeader_Parse_Armored()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "armored header test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, true, identity.Recipient);

        ciphertext.Position = 0;
        var header = AgeHeader.Parse(ciphertext);

        Assert.Equal(1, header.RecipientCount);
        Assert.True(header.IsArmored);
    }

    [Fact]
    public void RoundTrip_EmptyPlaintext()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Array.Empty<byte>();

        using var input = new MemoryStream(plaintext);
        using var headerOut = new MemoryStream();
        using var payloadOut = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, headerOut, payloadOut, identity.Recipient);

        headerOut.Position = 0;
        payloadOut.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.DecryptDetached(headerOut, payloadOut, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void RoundTrip_MultiRecipient()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();
        var plaintext = "multi-recipient detached"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var headerOut = new MemoryStream();
        using var payloadOut = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, headerOut, payloadOut, id1.Recipient, id2.Recipient);

        // Decrypt with second identity
        headerOut.Position = 0;
        payloadOut.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.DecryptDetached(headerOut, payloadOut, output, id2);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void RoundTrip_LargeMultiChunk()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var headerOut = new MemoryStream();
        using var payloadOut = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, headerOut, payloadOut, identity.Recipient);

        headerOut.Position = 0;
        payloadOut.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.DecryptDetached(headerOut, payloadOut, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void AgeHeader_Parse_ScryptStanza()
    {
        var recipient = new ScryptRecipient("test passphrase", workFactor: 10);
        var plaintext = "scrypt header test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, recipient);

        ciphertext.Position = 0;
        var header = AgeHeader.Parse(ciphertext);

        Assert.Equal(1, header.RecipientCount);
        Assert.Equal("scrypt", header.Recipients[0].Type);
    }

    [Fact]
    public void AgeHeader_Parse_NonSeekableStream()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "non-seekable header test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, identity.Recipient);

        ciphertext.Position = 0;
        using var nonSeekable = new NonSeekableStream(ciphertext);

        var header = AgeHeader.Parse(nonSeekable);

        Assert.False(header.IsArmored);
        Assert.True(header.RecipientCount > 0);
    }

    [Fact]
    public void AgeHeader_Parse_WrapsFormatException()
    {
        var text = "age-encryption.org/v1\n-> test\n@@@@\n\n--- AAAA\n";
        using var stream = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(text));

        var ex = Assert.Throws<AgeHeaderException>(() => AgeHeader.Parse(stream));
        Assert.Contains("header parse error", ex.Message);
    }

    private sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
