using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// <see cref="Age.DecryptWriter"/> — the push half of decryption. Its distinguishing
/// risk is that nothing is known up front: framing, header, nonce, and chunks are all
/// discovered from bytes as they arrive, and the final chunk is only recognisable as
/// final at dispose. These tests push ciphertext in shapes that stress those seams —
/// byte-at-a-time, exact chunk multiples, and truncation.
/// </summary>
public class DecryptWriterTests
{
    private static readonly int ChunkSize = 64 * 1024;

    private static byte[] Pattern(int length)
    {
        var data = new byte[length];
        for (var i = 0; i < length; i++)
            data[i] = (byte)(i * 31 + 7);
        return data;
    }

    private static byte[] PushDecrypt(byte[] ciphertext, IIdentity identity, int writeSize = int.MaxValue)
    {
        using var output = new MemoryStream();

        using (var writer = Age.DecryptWriter(output, identity))
            for (var offset = 0; offset < ciphertext.Length; offset += writeSize)
                writer.Write(ciphertext.AsSpan(offset, Math.Min(writeSize, ciphertext.Length - offset)));

        return output.ToArray();
    }

    // --- round trips ---------------------------------------------------------

    [Theory]
    [InlineData(0)]           // empty plaintext — the one case where an empty final chunk is legal
    [InlineData(1)]
    [InlineData(1000)]
    public void RoundTrip_SmallPayloads(int length)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(length);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, identity.Recipient), identity));
    }

    [Theory]
    [InlineData(-1)]  // one byte under a chunk
    [InlineData(0)]   // exactly one chunk — the boundary the hold-back rule turns on
    [InlineData(1)]   // one byte over
    public void RoundTrip_AtTheChunkBoundary(int delta)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + delta);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, identity.Recipient), identity));
    }

    [Fact]
    public void RoundTrip_ExactlyTwoChunks()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize * 2);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, identity.Recipient), identity));
    }

    [Fact]
    public void RoundTrip_MultiChunkPayload()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize * 3 + 12345);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, identity.Recipient), identity));
    }

    // --- write granularity is not allowed to matter --------------------------

    [Theory]
    [InlineData(1)]      // byte at a time: every stage transition lands mid-write
    [InlineData(7)]
    [InlineData(64)]
    [InlineData(4096)]
    public void RoundTrip_IsIndependentOfWriteSize(int writeSize)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 5000);
        var ciphertext = Age.Encrypt(plaintext, identity.Recipient);

        Assert.Equal(plaintext, PushDecrypt(ciphertext, identity, writeSize));
    }

    [Fact]
    public void ByteAtATime_AcrossTheChunkBoundary()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 1);
        var ciphertext = Age.Encrypt(plaintext, identity.Recipient);

        Assert.Equal(plaintext, PushDecrypt(ciphertext, identity, writeSize: 1));
    }

    // --- armor ---------------------------------------------------------------

    [Fact]
    public void Armored_IsAutoDetected()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(5000);
        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        Assert.Equal(plaintext, PushDecrypt(armored, identity));
    }

    [Fact]
    public void Armored_MultiChunk_ByteAtATime()
    {
        // Armor decoding is line-driven while writes are arbitrary, so the two
        // framings have to interleave correctly under the worst granularity.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 777);
        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        Assert.Equal(plaintext, PushDecrypt(armored, identity, writeSize: 1));
    }

    [Fact]
    public void RequireArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Pattern(100), identity.Recipient);
        var options = new AgeDecryptOptions { RequireArmor = true };

        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, options, identity);
            writer.Write(binary);
        });
    }

    [Fact]
    public void RequireArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(100);
        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
        var options = new AgeDecryptOptions { RequireArmor = true };

        using var output = new MemoryStream();
        using (var writer = Age.DecryptWriter(output, options, identity))
            writer.Write(armored);

        Assert.Equal(plaintext, output.ToArray());
    }

    // --- failure modes -------------------------------------------------------

    [Fact]
    public void Truncated_MidPayload_IsRejectedAtDispose()
    {
        // The final chunk is only knowable at dispose, so truncation must surface
        // there rather than passing silently as a short-but-valid file.
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(ChunkSize * 2), identity.Recipient);

        using var output = new MemoryStream();

        Assert.Throws<AgeAuthenticationException>(() =>
        {
            using var writer = Age.DecryptWriter(output, identity);
            writer.Write(ciphertext.AsSpan(0, ciphertext.Length - 100));
        });
    }

    [Fact]
    public void TruncatedInsideHeader_IsRejectedAtDispose()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), identity.Recipient);

        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, identity);
            writer.Write(ciphertext.AsSpan(0, 20));
        });

        Assert.Contains("before the age payload", ex.Message);
    }

    [Fact]
    public void NothingWritten_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, identity);
        });
    }

    [Fact]
    public void WrongIdentity_ThrowsFromTheWriteThatCompletesTheHeader()
    {
        // Documented asymmetry: unlike the other three streaming members, the key is
        // not known at construction, so a no-match surfaces from Write.
        using var identity = X25519Identity.Generate();
        using var stranger = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), identity.Recipient);

        using var output = new MemoryStream();
        using var writer = Age.DecryptWriter(output, stranger);

        Assert.Throws<NoIdentityMatchException>(() => writer.Write(ciphertext));
    }

    [Fact]
    public void TamperedPayload_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(500), identity.Recipient);
        ciphertext[^5] ^= 0xFF;

        using var output = new MemoryStream();

        Assert.ThrowsAny<AgeException>(() =>
        {
            using var writer = Age.DecryptWriter(output, identity);
            writer.Write(ciphertext);
        });
    }

    // --- stream contract -----------------------------------------------------

    [Fact]
    public void Stream_IsWriteOnlyAndNonSeekable()
    {
        using var identity = X25519Identity.Generate();
        using var output = new MemoryStream();
        using var writer = Age.DecryptWriter(output, identity);

        // Written up front so the trailing Dispose has a complete file to finalize;
        // disposing without one is itself an error, covered by NothingWritten_IsRejected.
        writer.Write(Age.Encrypt(Pattern(10), identity.Recipient));

        Assert.True(writer.CanWrite);
        Assert.False(writer.CanRead);
        Assert.False(writer.CanSeek);
        Assert.Throws<NotSupportedException>(() => writer.Length);
        Assert.Throws<NotSupportedException>(() => writer.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => writer.SetLength(0));
        Assert.Throws<NotSupportedException>(() => writer.Read(new byte[1], 0, 1));
    }

    [Fact]
    public void DestinationIsNotDisposed()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), identity.Recipient);

        using var inner = new MemoryStream();
        var output = new DisposeTrackingStream(inner);
        using (var writer = Age.DecryptWriter(output, identity))
            writer.Write(ciphertext);

        Assert.False(output.WasDisposed);
    }

    [Fact]
    public void WriteAfterDispose_Throws()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), identity.Recipient);

        using var output = new MemoryStream();
        var writer = Age.DecryptWriter(output, identity);
        writer.Write(ciphertext);
        writer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => writer.Write(ciphertext));
    }

    // --- async ---------------------------------------------------------------

    [Fact]
    public async Task WriteAsync_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 2048);
        var ciphertext = Age.Encrypt(plaintext, identity.Recipient);

        using var output = new MemoryStream();

        await using (var writer = Age.DecryptWriter(output, identity))
            await writer.WriteAsync(ciphertext);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task WriteAsync_NeverBlocksOnTheDestination()
    {
        // The destination faults on any synchronous write, pinning that the async
        // path stages plaintext and drains it with a real await.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize * 2 + 33);
        var ciphertext = Age.Encrypt(plaintext, identity.Recipient);

        using var inner = new MemoryStream();
        await using var output = new ThrowOnSyncIoStream(inner);

        await using (var writer = Age.DecryptWriter(output, identity))
            for (var offset = 0; offset < ciphertext.Length; offset += 8192)
                await writer.WriteAsync(ciphertext.AsMemory(offset, Math.Min(8192, ciphertext.Length - offset)));

        Assert.Equal(plaintext, inner.ToArray());
    }

    [Fact]
    public async Task DisposeAsync_FinalizesTheLastChunk()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(777);
        var ciphertext = Age.Encrypt(plaintext, identity.Recipient);

        using var inner = new MemoryStream();
        await using var output = new ThrowOnSyncIoStream(inner);

        var writer = Age.DecryptWriter(output, identity);
        await writer.WriteAsync(ciphertext);
        await writer.DisposeAsync();

        Assert.Equal(plaintext, inner.ToArray());
    }

    private sealed class DisposeTrackingStream(Stream inner) : Stream
    {
        public bool WasDisposed { get; private set; }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override void Write(ReadOnlySpan<byte> buffer) => inner.Write(buffer);
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    // --- the grid is closed --------------------------------------------------

    [Fact]
    public void EveryCellOfTheStreamingGridExists()
    {
        var members = typeof(Age).GetMethods().Select(m => m.Name).ToHashSet();

        Assert.Contains("EncryptReader", members);
        Assert.Contains("EncryptWriter", members);
        Assert.Contains("DecryptReader", members);
        Assert.Contains("DecryptWriter", members);
    }
}
