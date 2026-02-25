using Age;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class RandomAccessTests
{
    [Fact]
    public void Sequential_ReadAt_MatchesFullDecrypt()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);

        // Full decrypt for comparison
        ciphertext.Position = 0;
        using var fullDecOutput = new MemoryStream();
        AgeEncrypt.Decrypt(ciphertext, fullDecOutput, identity);
        var expected = fullDecOutput.ToArray();

        // Sequential read via ReadAt
        ciphertext.Position = 0;
        using var ra = new AgeRandomAccess(ciphertext, identity);

        var actual = new byte[plaintext.Length];
        int totalRead = 0;
        while (totalRead < actual.Length)
        {
            int read = ra.ReadAt(totalRead, actual.AsSpan(totalRead));
            Assert.True(read > 0);
            totalRead += read;
        }

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MidChunk_Offset()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        // Read from middle of first chunk
        int offset = 32768;
        var buf = new byte[100];
        int read = ra.ReadAt(offset, buf);
        Assert.Equal(100, read);
        Assert.Equal(plaintext.AsSpan(offset, 100).ToArray(), buf);
    }

    [Fact]
    public void CrossChunk_Boundary()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        // Read across chunk boundary (64 KiB = 65536)
        int offset = 65530;
        var buf = new byte[100];
        int read = ra.ReadAt(offset, buf);
        Assert.Equal(100, read);
        Assert.Equal(plaintext.AsSpan(offset, 100).ToArray(), buf);
    }

    [Fact]
    public void FirstByte()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "Hello, random access!"u8.ToArray();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        var buf = new byte[1];
        int read = ra.ReadAt(0, buf);
        Assert.Equal(1, read);
        Assert.Equal((byte)'H', buf[0]);
    }

    [Fact]
    public void LastByte()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "Hello, random access!"u8.ToArray();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        var buf = new byte[1];
        int read = ra.ReadAt(plaintext.Length - 1, buf);
        Assert.Equal(1, read);
        Assert.Equal((byte)'!', buf[0]);
    }

    [Fact]
    public void ReadPastEnd_ReturnsZero()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "short"u8.ToArray();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        var buf = new byte[10];
        int read = ra.ReadAt(plaintext.Length, buf);
        Assert.Equal(0, read);
    }

    [Fact]
    public void ChunkEdge_Reads()
    {
        using var identity = X25519Identity.Generate();
        // 2 full chunks + partial
        var plaintext = new byte[65536 * 2 + 1000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        // Read last byte of chunk 0
        var buf1 = new byte[1];
        ra.ReadAt(65535, buf1);
        Assert.Equal(plaintext[65535], buf1[0]);

        // Read first byte of chunk 1
        var buf2 = new byte[1];
        ra.ReadAt(65536, buf2);
        Assert.Equal(plaintext[65536], buf2[0]);
    }

    [Fact]
    public void GetStream_SeekAndRead()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        using var stream = ra.GetStream();
        Assert.True(stream.CanSeek);
        Assert.True(stream.CanRead);

        // Seek to offset 50000
        stream.Seek(50000, SeekOrigin.Begin);
        var buf = new byte[100];
        int read = stream.Read(buf);
        Assert.Equal(100, read);
        Assert.Equal(plaintext.AsSpan(50000, 100).ToArray(), buf);

        // Verify Position advanced
        Assert.Equal(50100, stream.Position);
    }

    [Fact]
    public void GetStream_ReadAll()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        using var stream = ra.GetStream();
        using var output = new MemoryStream();
        stream.CopyTo(output);
        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void EmptyPlaintext()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Array.Empty<byte>();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        Assert.Equal(0, ra.PlaintextLength);

        var buf = new byte[10];
        int read = ra.ReadAt(0, buf);
        Assert.Equal(0, read);
    }

    [Fact]
    public void SingleChunk_ExactSize()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[64 * 1024]; // Exactly one chunk
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        Assert.Equal(plaintext.Length, ra.PlaintextLength);

        // Read last byte
        var buf = new byte[1];
        int read = ra.ReadAt(plaintext.Length - 1, buf);
        Assert.Equal(1, read);
        Assert.Equal(plaintext[^1], buf[0]);
    }

    [Fact]
    public void PlaintextLength_Correct()
    {
        using var identity = X25519Identity.Generate();

        foreach (var size in new[] { 0, 1, 100, 65535, 65536, 65537, 100_000, 131072 })
        {
            var plaintext = new byte[size];
            if (size > 0) new Random(42).NextBytes(plaintext);

            using var ciphertext = Encrypt(plaintext, identity.Recipient);
            using var ra = new AgeRandomAccess(ciphertext, identity);

            Assert.Equal(size, ra.PlaintextLength);
        }
    }

    [Fact]
    public void MultiChunk_Span()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[200_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        // Read a span that crosses 2 chunk boundaries
        int offset = 65000;
        int length = 70000; // Crosses from chunk 0 into chunk 1, into chunk 2
        var buf = new byte[length];
        int totalRead = 0;
        while (totalRead < length)
        {
            int read = ra.ReadAt(offset + totalRead, buf.AsSpan(totalRead));
            Assert.True(read > 0);
            totalRead += read;
        }
        Assert.Equal(plaintext.AsSpan(offset, length).ToArray(), buf);
    }

    [Fact]
    public void Armored_RandomAccess()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "armored random access test data!"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        var ciphertext = new MemoryStream();
        AgeEncrypt.Encrypt(input, ciphertext, armor: true, identity.Recipient);
        ciphertext.Position = 0;

        using var ra = new AgeRandomAccess(ciphertext, identity);
        var buf = new byte[plaintext.Length];
        var totalRead = 0;
        while (totalRead < buf.Length)
        {
            var read = ra.ReadAt(totalRead, buf.AsSpan(totalRead));
            Assert.True(read > 0);
            totalRead += read;
        }

        Assert.Equal(plaintext, buf);
    }

    [Fact]
    public void NonSeekableStream_Rejected()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "test"u8.ToArray();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var nonSeekable = new NonSeekableStream(ciphertext);

        Assert.Throws<ArgumentException>(() => new AgeRandomAccess(nonSeekable, identity));
    }

    [Fact]
    public void Seek_SeekOriginCurrent()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);
        using var stream = ra.GetStream();

        // Seek to 10000 from begin, then +5000 from current
        stream.Seek(10000, SeekOrigin.Begin);
        stream.Seek(5000, SeekOrigin.Current);
        Assert.Equal(15000, stream.Position);

        var buf = new byte[100];
        var read = stream.Read(buf);
        Assert.Equal(100, read);
        Assert.Equal(plaintext.AsSpan(15000, 100).ToArray(), buf);
    }

    [Fact]
    public void Seek_SeekOriginEnd()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);
        using var stream = ra.GetStream();

        stream.Seek(-10, SeekOrigin.End);
        Assert.Equal(plaintext.Length - 10, stream.Position);

        var buf = new byte[10];
        var read = stream.Read(buf);
        Assert.Equal(10, read);
        Assert.Equal(plaintext.AsSpan(plaintext.Length - 10, 10).ToArray(), buf);
    }

    [Fact]
    public void NegativeOffset_ReadAt_ReturnsZero()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "test"u8.ToArray();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var ra = new AgeRandomAccess(ciphertext, identity);

        var buf = new byte[10];
        var read = ra.ReadAt(-1, buf);
        Assert.Equal(0, read);
    }

    private static MemoryStream Encrypt(byte[] plaintext, IRecipient recipient)
    {
        using var input = new MemoryStream(plaintext);
        var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, recipient);
        output.Position = 0;
        return output;
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
