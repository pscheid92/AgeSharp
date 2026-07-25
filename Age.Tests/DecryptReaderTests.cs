using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Tests for the unified <see cref="Age.DecryptReader(System.IO.Stream, [System.ReadOnlySpan{IIdentity}])" />
///     decrypt stream: seekable random access over a seekable source (ported from the old
///     <c>AgeRandomAccess</c> suite), the one-chunk cache, forward-only behavior over a
///     non-seekable source, and truncation-detection semantics.
/// </summary>
public class DecryptReaderTests
{
    private static MemoryStream Encrypt(byte[] plaintext, IRecipient recipient, bool armor = false)
    {
        using var input = new MemoryStream(plaintext);
        var output = new MemoryStream();
        Age.Encrypt(input, output, [recipient], new AgeEncryptOptions { Armor = armor });
        output.Position = 0;
        return output;
    }

    private static byte[] ReadAt(Stream stream, long offset, int count)
    {
        stream.Position = offset;
        var buf = new byte[count];
        var total = 0;
        while (total < count)
        {
            var read = stream.Read(buf.AsSpan(total));
            if (read == 0) break;
            total += read;
        }

        return total == count ? buf : buf[..total];
    }

    // --- Seekable capabilities and plaintext length ---

    [Fact]
    public void SeekableSource_ReportsCapabilitiesAndLength()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.True(stream.CanRead);
        Assert.True(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Equal(plaintext.Length, stream.Length);
    }

    [Fact]
    public void PlaintextLength_Correct_AcrossSizes()
    {
        using var identity = X25519Identity.Generate();

        foreach (var size in new[] { 0, 1, 100, 65535, 65536, 65537, 100_000, 131072, 196608 })
        {
            var plaintext = new byte[size];
            if (size > 0) new Random(42).NextBytes(plaintext);

            using var ciphertext = Encrypt(plaintext, identity.Recipient);
            using var stream = Age.DecryptReader(ciphertext, [identity]);

            Assert.Equal(size, stream.Length);
        }
    }

    // --- Sequential read matches a full decrypt, byte-for-byte ---

    [Fact]
    public void Sequential_Read_MatchesFullDecrypt()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        using var output = new MemoryStream();
        stream.CopyTo(output);
        Assert.Equal(plaintext, output.ToArray());
    }

    // --- The seekable path and the forward-only path agree byte-for-byte ---

    [Fact]
    public void SeekablePath_And_ForwardOnlyPath_ByteIdentical()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[200_000];
        new Random(7).NextBytes(plaintext);

        var ciphertextBytes = Encrypt(plaintext, identity.Recipient).ToArray();

        using var seekableStream = Age.DecryptReader(new MemoryStream(ciphertextBytes), [identity]);
        using var seekableOut = new MemoryStream();
        seekableStream.CopyTo(seekableOut);

        using var forwardStream = Age.DecryptReader(new NonSeekableStream(new MemoryStream(ciphertextBytes)), [identity]);
        using var forwardOut = new MemoryStream();
        forwardStream.CopyTo(forwardOut);

        Assert.False(forwardStream.CanSeek);
        Assert.Equal(seekableOut.ToArray(), forwardOut.ToArray());
        Assert.Equal(plaintext, seekableOut.ToArray());
    }

    // --- Offsets: mid-chunk, cross-chunk, first/last byte, chunk edges ---

    [Fact]
    public void MidChunk_And_CrossChunk_Offsets()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[200_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Equal(plaintext.AsSpan(32768, 100).ToArray(), ReadAt(stream, 32768, 100)); // mid first chunk
        Assert.Equal(plaintext.AsSpan(65530, 100).ToArray(), ReadAt(stream, 65530, 100)); // across chunk 0/1
        Assert.Equal(plaintext[..1], ReadAt(stream, 0, 1)); // first byte
        Assert.Equal(plaintext[^1..], ReadAt(stream, plaintext.Length - 1, 1)); // last byte
    }

    [Fact]
    public void ChunkBoundary_Reads()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[65536 * 2 + 1000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Equal(plaintext[65535], ReadAt(stream, 65535, 1)[0]); // last byte of chunk 0
        Assert.Equal(plaintext[65536], ReadAt(stream, 65536, 1)[0]); // first byte of chunk 1
    }

    [Fact]
    public void MultiChunk_Span_CrossesTwoBoundaries()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[200_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        const int offset = 65000;
        const int length = 70000; // chunk 0 → chunk 1 → chunk 2
        Assert.Equal(plaintext.AsSpan(offset, length).ToArray(), ReadAt(stream, offset, length));
    }

    // --- Empty and single-chunk plaintext ---

    [Fact]
    public void EmptyPlaintext_LengthZero_ReadReturnsZero()
    {
        using var identity = X25519Identity.Generate();

        using var ciphertext = Encrypt([], identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Equal(0, stream.Length);
        Assert.Equal(0, stream.Read(new byte[10], 0, 10));
    }

    [Fact]
    public void SingleChunk_ExactSize()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[64 * 1024];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Equal(plaintext.Length, stream.Length);
        Assert.Equal(plaintext[^1..], ReadAt(stream, plaintext.Length - 1, 1));
    }

    // --- Seeking: origins, past-end, backward, exact boundaries ---

    [Fact]
    public void Seek_Origins()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        stream.Seek(10000, SeekOrigin.Begin);
        Assert.Equal(10000, stream.Position);
        stream.Seek(5000, SeekOrigin.Current);
        Assert.Equal(15000, stream.Position);
        Assert.Equal(plaintext.AsSpan(15000, 100).ToArray(), ReadAt(stream, 15000, 100));

        stream.Seek(-10, SeekOrigin.End);
        Assert.Equal(plaintext.Length - 10, stream.Position);
        Assert.Equal(plaintext.AsSpan(plaintext.Length - 10, 10).ToArray(), ReadAt(stream, plaintext.Length - 10, 10));
    }

    [Fact]
    public void Seek_PastEnd_ReadReturnsZero_PositionUnchanged()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "short"u8.ToArray();

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        stream.Seek(1000, SeekOrigin.Begin);
        Assert.Equal(1000, stream.Position);

        var buf = new byte[10];
        Assert.Equal(0, stream.Read(buf, 0, buf.Length));
        Assert.Equal(1000, stream.Position);
    }

    [Fact]
    public void Seek_Backward_RereadsCorrectly()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[200_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        // Read forward into chunk 2, then seek back into chunk 0 and re-read.
        Assert.Equal(plaintext.AsSpan(150000, 50).ToArray(), ReadAt(stream, 150000, 50));
        Assert.Equal(plaintext.AsSpan(10, 50).ToArray(), ReadAt(stream, 10, 50));
    }

    [Fact]
    public void Seek_NegativeAbsolute_Throws()
    {
        using var identity = X25519Identity.Generate();
        using var ciphertext = Encrypt("data"u8.ToArray(), identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Throws<ArgumentOutOfRangeException>(() => stream.Seek(-1, SeekOrigin.Begin));
        Assert.Throws<ArgumentOutOfRangeException>(() => stream.Position = -1);
    }

    // --- One-chunk cache: byte-by-byte reads decrypt each chunk exactly once ---

    [Fact]
    public void ChunkCache_ByteByByte_DecryptsEachChunkOnce()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[65536 * 2 + 5000]; // three chunks
        new Random(42).NextBytes(plaintext);

        var ciphertextBytes = Encrypt(plaintext, identity.Recipient).ToArray();
        var payloadOffset = (int)Age.ReadHeader(new MemoryStream(ciphertextBytes)).PayloadOffset;
        var totalEncryptedPayload = ciphertextBytes.Length - payloadOffset - 16; // minus the 16-byte nonce

        var counting = new CountingStream(new MemoryStream(ciphertextBytes));
        using var stream = Age.DecryptReader(counting, [identity]);

        // Reset after the header/nonce read so only payload reads are counted.
        counting.Reset();

        var output = new byte[plaintext.Length];
        for (var i = 0; i < output.Length; i++)
            Assert.Equal(1, stream.Read(output.AsSpan(i, 1)));

        Assert.Equal(plaintext, output);
        // With the cache, each chunk's ciphertext is read exactly once despite ~135k reads.
        Assert.Equal(totalEncryptedPayload, counting.TotalBytesRead);
    }

    // --- Armored sources are forward-only, whatever the transport ---

    [Fact]
    public void ArmoredSeekableSource_IsSeekable_AndRoundTrips()
    {
        // Armor is an order-preserving, position-computable transform — 48 bytes per
        // 64 columns, only the last line short — so a binary offset translates to a
        // text position arithmetically. Seeking costs neither the file's size in RAM
        // (the 0.2 behaviour) nor a full scan to find the end (rage's approach); the
        // geometry comes from bounded probes at each end.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient, true);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.Length, stream.Length);

        using var output = new MemoryStream();
        stream.CopyTo(output);
        Assert.Equal(plaintext, output.ToArray());
    }

    // --- Non-seekable source stays forward-only ---

    [Fact]
    public void NonSeekableSource_IsForwardOnly()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "forward only"u8.ToArray();

        var ciphertextBytes = Encrypt(plaintext, identity.Recipient).ToArray();
        using var stream = Age.DecryptReader(new NonSeekableStream(new MemoryStream(ciphertextBytes)), [identity]);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);

        using var output = new MemoryStream();
        stream.CopyTo(output);
        Assert.Equal(plaintext, output.ToArray());
    }

    // --- Truncation is only detectable once a read reaches the affected chunk ---

    [Fact]
    public void FinalChunkTampering_IsDetectedAtOpen()
    {
        // The final chunk is decrypted as a final chunk while opening, which is what
        // authenticates the plaintext length. Tampering with it is therefore caught
        // before any read, not on reaching it — earlier this opened cleanly and only
        // failed once a read touched the last chunk.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[65536 * 2 + 500]; // three chunks
        new Random(42).NextBytes(plaintext);

        var ciphertextBytes = Encrypt(plaintext, identity.Recipient).ToArray();

        // Corrupt the final byte (part of the last chunk's tag).
        ciphertextBytes[^1] ^= 0x01;

        Assert.Throws<AgeAuthenticationException>(() =>
            Age.DecryptReader(new MemoryStream(ciphertextBytes), [identity]));
    }

    [Fact]
    public void EarlierChunksStillReadIndependently()
    {
        // Authenticating the length must not turn every read into a whole-file check:
        // a chunk in the middle is still decrypted on its own.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[65536 * 2 + 500];
        new Random(7).NextBytes(plaintext);

        using var ciphertext = Encrypt(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Equal(plaintext.AsSpan(70_000, 100).ToArray(), ReadAt(stream, 70_000, 100));
    }

    // --- Read after dispose throws ---

    [Fact]
    public void ReadAfterDispose_Throws()
    {
        using var identity = X25519Identity.Generate();
        using var ciphertext = Encrypt("data"u8.ToArray(), identity.Recipient);
        var stream = Age.DecryptReader(ciphertext, [identity]);
        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[4], 0, 4));
    }

    [Fact]
    public void SeekableSource_UnderDeliversVsLength_ThrowsAuthentication()
    {
        using var identity = X25519Identity.Generate();
        var ciphertextBytes = Encrypt("payload"u8.ToArray(), identity.Recipient).ToArray();

        // A seekable source that claims more bytes than it can actually deliver: the
        // chunk math trusts Length, so loading the (over-sized) final chunk hits the
        // "could not read full chunk" guard — now while opening, since that is when
        // the final chunk is read to authenticate the length.
        using var lying = new InflatedLengthStream(new MemoryStream(ciphertextBytes), 64);

        Assert.Throws<AgeAuthenticationException>(() => Age.DecryptReader(lying, [identity]));
    }

    [Fact]
    public void SeekableStream_ContractMembers()
    {
        using var identity = X25519Identity.Generate();
        using var ciphertext = Encrypt("data"u8.ToArray(), identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, [identity]);

        stream.Flush(); // no-op, must not throw
        Assert.Throws<ArgumentOutOfRangeException>(() => stream.Seek(0, (SeekOrigin)999));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(10));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
    }

    /// <summary>Counts payload bytes actually read from the ciphertext, to prove the chunk cache works.</summary>
    private sealed class CountingStream(MemoryStream inner) : Stream
    {
        public long TotalBytesRead { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public void Reset()
        {
            TotalBytesRead = 0;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = inner.Read(buffer, offset, count);
            TotalBytesRead += n;
            return n;
        }

        public override int Read(Span<byte> buffer)
        {
            var n = inner.Read(buffer);
            TotalBytesRead += n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return inner.Seek(offset, origin);
        }

        public override void Flush()
        {
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>A seekable stream that reports a Length larger than its backing data can deliver.</summary>
    private sealed class InflatedLengthStream(MemoryStream inner, long extra) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => inner.Length + extra;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return inner.Read(buffer, offset, count);
        }

        public override int Read(Span<byte> buffer)
        {
            return inner.Read(buffer);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return inner.Seek(offset, origin);
        }

        public override void Flush()
        {
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}