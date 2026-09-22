using Age.Crypto;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Once a Read on an encrypt or decrypt stream has thrown, every later Read throws the same
/// exception. A stream that carried on would resume from a state the failure had already
/// half-consumed: the encrypt side drops its look-ahead byte and emits authentic ciphertext of
/// the wrong plaintext, and the decrypt side skips whatever failed to authenticate.
/// </summary>
public class FailStopStreamTests
{
    private const int PayloadNonceSize = 16;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptReader_AfterSourceFails_KeepsFailing(bool armor)
    {
        using var identity = X25519Identity.Generate();
        using var source = new FailsOnceStream(new MemoryStream(Plaintext(200_000)), failingRead: 3);
        using var encrypted = AgeEncrypt.EncryptReader(source, armor, identity.Recipient);

        var first = Assert.Throws<IOException>(() => DrainOneByteAtATime(encrypted));
        var retry = Assert.Throws<IOException>(() => DrainOneByteAtATime(encrypted));

        Assert.Same(first, retry);
    }

    [Fact]
    public void DecryptReader_AfterChunkFailsAuthentication_KeepsFailing()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Plaintext(3 * StreamEncryption.ChunkSize + 10);
        var ciphertext = Encrypt(plaintext, identity.Recipient);

        // Garbage one byte longer than a chunk after chunk 0: the failed read consumes it all,
        // so a stream that carried on would land exactly on the genuine chunk 1.
        var payloadStart = (int)AgeHeader.Parse(new MemoryStream(ciphertext)).PayloadOffset + PayloadNonceSize;
        var chunk1Start = payloadStart + StreamEncryption.EncryptedChunkSize;
        byte[] tampered =
        [
            .. ciphertext.AsSpan(0, chunk1Start),
            .. new byte[StreamEncryption.EncryptedChunkSize + 1],
            .. ciphertext.AsSpan(chunk1Start),
        ];

        using var decrypted = AgeEncrypt.DecryptReader(new MemoryStream(tampered), identity);

        var first = Assert.Throws<AgePayloadException>(() => Drain(decrypted));
        var retry = Assert.Throws<AgePayloadException>(() => Drain(decrypted));

        Assert.Same(first, retry);
    }

    [Fact]
    public void DecryptReader_AfterSourceFails_KeepsFailing()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(Plaintext(200_000), identity.Recipient);

        // Header parsing makes one Read per byte and the nonce one more, so this fails the Read
        // for the second payload chunk.
        var headerReads = (int)AgeHeader.Parse(new MemoryStream(ciphertext)).PayloadOffset + 1;
        using var source = new FailsOnceStream(new MemoryStream(ciphertext), failingRead: headerReads + 2);
        using var decrypted = AgeEncrypt.DecryptReader(source, identity);

        var first = Assert.Throws<IOException>(() => Drain(decrypted));
        var retry = Assert.Throws<IOException>(() => Drain(decrypted));

        Assert.Same(first, retry);
    }

    private static byte[] Plaintext(int length)
    {
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] = (byte)(i * 7 + 3);
        return bytes;
    }

    private static byte[] Encrypt(byte[] plaintext, IRecipient recipient)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(plaintext), output, recipient);
        return output.ToArray();
    }

    // One byte per Read, so a failure never discards output the caller already received — only
    // the stream's own state can go wrong.
    private static void DrainOneByteAtATime(Stream stream)
    {
        var buffer = new byte[1];
        while (stream.Read(buffer) > 0) { }
    }

    private static void Drain(Stream stream)
    {
        var buffer = new byte[4096];
        while (stream.Read(buffer) > 0) { }
    }

    /// <summary>A source whose <paramref name="failingRead"/>-th Read throws; every other Read succeeds.</summary>
    private sealed class FailsOnceStream(Stream inner, int failingRead) : Stream
    {
        private int _reads;

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer) =>
            ++_reads == failingRead
                ? throw new IOException("transient source failure")
                : inner.Read(buffer);

        public override int ReadByte()
        {
            Span<byte> one = stackalloc byte[1];
            return Read(one) == 0 ? -1 : one[0];
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                inner.Dispose();

            base.Dispose(disposing);
        }
    }
}
