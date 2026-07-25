using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     <see cref="Age.DecryptWriter" /> — the push half of decryption. Its distinguishing
///     risk is that nothing is known up front: framing, header, nonce, and chunks are all
///     discovered from bytes as they arrive, and the final chunk is only recognisable as
///     final at dispose. These tests push ciphertext in shapes that stress those seams —
///     byte-at-a-time, exact chunk multiples, and truncation.
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

        using (var writer = Age.DecryptWriter(output, [identity]))
        {
            for (var offset = 0; offset < ciphertext.Length; offset += writeSize)
                writer.Write(ciphertext.AsSpan(offset, Math.Min(writeSize, ciphertext.Length - offset)));
        }

        return output.ToArray();
    }

    // --- round trips ---------------------------------------------------------

    [Theory]
    [InlineData(0)] // empty plaintext — the one case where an empty final chunk is legal
    [InlineData(1)]
    [InlineData(1000)]
    public void RoundTrip_SmallPayloads(int length)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(length);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, [identity.Recipient]), identity));
    }

    [Theory]
    [InlineData(-1)] // one byte under a chunk
    [InlineData(0)] // exactly one chunk — the boundary the hold-back rule turns on
    [InlineData(1)] // one byte over
    public void RoundTrip_AtTheChunkBoundary(int delta)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + delta);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, [identity.Recipient]), identity));
    }

    [Fact]
    public void RoundTrip_ExactlyTwoChunks()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize * 2);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, [identity.Recipient]), identity));
    }

    [Fact]
    public void RoundTrip_MultiChunkPayload()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize * 3 + 12345);

        Assert.Equal(plaintext, PushDecrypt(Age.Encrypt(plaintext, [identity.Recipient]), identity));
    }

    // --- write granularity is not allowed to matter --------------------------

    [Theory]
    [InlineData(1)] // byte at a time: every stage transition lands mid-write
    [InlineData(7)]
    [InlineData(64)]
    [InlineData(4096)]
    public void RoundTrip_IsIndependentOfWriteSize(int writeSize)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 5000);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        Assert.Equal(plaintext, PushDecrypt(ciphertext, identity, writeSize));
    }

    [Fact]
    public void ByteAtATime_AcrossTheChunkBoundary()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 1);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        Assert.Equal(plaintext, PushDecrypt(ciphertext, identity, 1));
    }

    // --- armor ---------------------------------------------------------------

    [Fact]
    public void Armored_IsAutoDetected()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(5000);
        var armored = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = true });

        Assert.Equal(plaintext, PushDecrypt(armored, identity));
    }

    [Fact]
    public void Armored_MultiChunk_ByteAtATime()
    {
        // Armor decoding is line-driven while writes are arbitrary, so the two
        // framings have to interleave correctly under the worst granularity.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 777);
        var armored = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = true });

        Assert.Equal(plaintext, PushDecrypt(armored, identity, 1));
    }

    [Fact]
    public void RequireArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Pattern(100), [identity.Recipient]);
        var options = new AgeDecryptOptions { RequireArmor = true };

        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity], options);
            writer.Write(binary);
        });
    }

    [Fact]
    public void RequireArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(100);
        var armored = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = true });
        var options = new AgeDecryptOptions { RequireArmor = true };

        using var output = new MemoryStream();
        using (var writer = Age.DecryptWriter(output, [identity], options))
        {
            writer.Write(armored);
        }

        Assert.Equal(plaintext, output.ToArray());
    }

    // --- failure modes -------------------------------------------------------

    [Fact]
    public void Truncated_MidPayload_IsRejectedAtDispose()
    {
        // The final chunk is only knowable at dispose, so truncation must surface
        // there rather than passing silently as a short-but-valid file.
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(ChunkSize * 2), [identity.Recipient]);

        using var output = new MemoryStream();

        Assert.Throws<AgeAuthenticationException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(ciphertext.AsSpan(0, ciphertext.Length - 100));
        });
    }

    [Fact]
    public void TruncatedInsideHeader_IsRejectedAtDispose()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
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
            using var writer = Age.DecryptWriter(output, [identity]);
        });
    }

    [Fact]
    public void WrongIdentity_ThrowsFromTheWriteThatCompletesTheHeader()
    {
        // Documented asymmetry: unlike the other three streaming members, the key is
        // not known at construction, so a no-match surfaces from Write.
        using var identity = X25519Identity.Generate();
        using var stranger = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var output = new MemoryStream();
        using var writer = Age.DecryptWriter(output, [stranger]);

        Assert.Throws<NoIdentityMatchException>(() => writer.Write(ciphertext));
    }

    [Fact]
    public void TamperedPayload_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(500), [identity.Recipient]);
        ciphertext[^5] ^= 0xFF;

        using var output = new MemoryStream();

        Assert.ThrowsAny<AgeException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(ciphertext);
        });
    }

    // --- malformed payloads --------------------------------------------------

    private static byte[] HeaderAndNonce(byte[] ciphertext)
    {
        var offset = (int)Age.ReadHeader(new MemoryStream(ciphertext)).PayloadOffset;
        return ciphertext[..(offset + 16)]; // header + payload nonce, zero chunks
    }

    [Fact]
    public void HeaderAndNonceOnly_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var truncated = HeaderAndNonce(Age.Encrypt(Pattern(100), [identity.Recipient]));

        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeAuthenticationException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(truncated);
        });

        Assert.Contains("no chunks", ex.Message);
    }

    [Fact]
    public void ChunkShorterThanTheAuthenticationTag_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);
        var offset = (int)Age.ReadHeader(new MemoryStream(ciphertext)).PayloadOffset;
        var stub = ciphertext[..(offset + 16 + 5)]; // five bytes is not even a tag

        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeAuthenticationException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(stub);
        });

        Assert.Contains("chunk too small", ex.Message);
    }

    [Fact]
    public void TruncatedInsideThePayloadNonce_IsRejected()
    {
        // The header parsed, so a file key is live when finalization fails — this is
        // the path that must still zero it on the way out.
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);
        var offset = (int)Age.ReadHeader(new MemoryStream(ciphertext)).PayloadOffset;

        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(ciphertext.AsSpan(0, offset + 4));
        });
    }

    [Fact]
    public void EmptyFinalChunkAfterData_IsRejected()
    {
        // STREAM rule: an empty final chunk is legal only for empty plaintext. No
        // encoder emits this and truncation cannot fake it — the AEAD tag fails
        // first — so the file is forged with a known payload key, which is exactly
        // the adversarial shape the check defends against.
        using var identity = X25519Identity.Generate();

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var header = new Header();
        header.Stanzas.Add(identity.Recipient.Wrap(fileKey));
        using var headerBytes = new MemoryStream();
        header.WriteTo(headerBytes, fileKey);

        var nonce = new byte[16];
        RandomNumberGenerator.Fill(nonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, nonce, "payload", 32);

        var full = StreamEncryption.EncryptChunk(payloadKey, 0, false, new byte[ChunkSize]);
        var emptyFinal = StreamEncryption.EncryptChunk(payloadKey, 1, true, []);
        var forged = (byte[])[.. headerBytes.ToArray(), .. nonce, .. full, .. emptyFinal];

        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeAuthenticationException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(forged);
        });

        Assert.Contains("final STREAM chunk is empty", ex.Message);
    }

    // --- armor edge cases ----------------------------------------------------

    [Fact]
    public void Armored_WithoutATrailingNewline_RoundTrips()
    {
        // Plenty of tools omit the final newline; the last line then only completes
        // at end of input rather than on an LF.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(300);
        var armored = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = true });

        var trimmed = armored[^1] == (byte)'\n' ? armored[..^1] : armored;
        Assert.Equal(plaintext, PushDecrypt(trimmed, identity));
    }

    [Fact]
    public void Armored_TruncatedBeforeTheEndMarker_IsRejected()
    {
        // Cut mid-body with no trailing newline: the last partial line still decodes
        // to real bytes at end of input, and the missing end marker is what rejects it.
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Pattern(4000), [identity.Recipient], new AgeEncryptOptions { Armor = true });
        var text = Encoding.ASCII.GetString(armored);

        var lines = text.Split('\n');
        var cut = string.Join('\n', lines[..(lines.Length / 2)]) + "\n" + lines[lines.Length / 2][..20];

        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = Age.DecryptWriter(output, [identity]);
            writer.Write(Encoding.ASCII.GetBytes(cut));
        });
    }

    [Fact]
    public void Armored_WithLeadingWhitespace_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(300);
        var armored = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = true });
        var padded = (byte[])[.. "\n\n   \n"u8, .. armored];

        Assert.Equal(plaintext, PushDecrypt(padded, identity));
    }

    // --- stream contract -----------------------------------------------------

    [Fact]
    public void Stream_IsWriteOnlyAndNonSeekable()
    {
        using var identity = X25519Identity.Generate();
        using var output = new MemoryStream();
        using var writer = Age.DecryptWriter(output, [identity]);

        // Written up front so the trailing Dispose has a complete file to finalize;
        // disposing without one is itself an error, covered by NothingWritten_IsRejected.
        writer.Write(Age.Encrypt(Pattern(10), [identity.Recipient]));

        Assert.True(writer.CanWrite);
        Assert.False(writer.CanRead);
        Assert.False(writer.CanSeek);
        Assert.Throws<NotSupportedException>(() => writer.Length);
        Assert.Throws<NotSupportedException>(() => writer.Position);
        Assert.Throws<NotSupportedException>(() => writer.Position = 0);
        Assert.Throws<NotSupportedException>(() => writer.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => writer.SetLength(0));
        Assert.Throws<NotSupportedException>(() => writer.Read(new byte[1], 0, 1));

        writer.Flush();
    }

    [Fact]
    public async Task ArrayOverloads_AndFlush_ForwardCorrectly()
    {
        // Stream's byte[]-based Write overloads are what BCL helpers like CopyTo
        // actually call, so they carry real traffic rather than being ceremony.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(3000);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        using var output = new MemoryStream();

        using (var writer = Age.DecryptWriter(output, [identity]))
        {
            writer.Write(ciphertext, 0, 100);
            await writer.WriteAsync(ciphertext, 100, ciphertext.Length - 100);
            await writer.FlushAsync();
        }

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void CopyTo_DrivesItEndToEnd()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize + 99);
        using var source = new MemoryStream(Age.Encrypt(plaintext, [identity.Recipient]));
        using var output = new MemoryStream();

        using (var writer = Age.DecryptWriter(output, [identity]))
        {
            source.CopyTo(writer);
        }

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void DestinationIsNotDisposed()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var inner = new MemoryStream();
        var output = new DisposeTrackingStream(inner);
        using (var writer = Age.DecryptWriter(output, [identity]))
        {
            writer.Write(ciphertext);
        }

        Assert.False(output.WasDisposed);
    }

    [Fact]
    public void WriteAfterDispose_Throws()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var output = new MemoryStream();
        var writer = Age.DecryptWriter(output, [identity]);
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
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        using var output = new MemoryStream();

        await using (var writer = Age.DecryptWriter(output, [identity]))
        {
            await writer.WriteAsync(ciphertext);
        }

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task WriteAsync_NeverBlocksOnTheDestination()
    {
        // The destination faults on any synchronous write, pinning that the async
        // path stages plaintext and drains it with a real await.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(ChunkSize * 2 + 33);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        using var inner = new MemoryStream();
        await using var output = new ThrowOnSyncIoStream(inner);

        await using (var writer = Age.DecryptWriter(output, [identity]))
        {
            for (var offset = 0; offset < ciphertext.Length; offset += 8192)
                await writer.WriteAsync(ciphertext.AsMemory(offset, Math.Min(8192, ciphertext.Length - offset)));
        }

        Assert.Equal(plaintext, inner.ToArray());
    }

    [Fact]
    public async Task DisposeAsync_FinalizesTheLastChunk()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(777);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        using var inner = new MemoryStream();
        await using var output = new ThrowOnSyncIoStream(inner);

        var writer = Age.DecryptWriter(output, [identity]);
        await writer.WriteAsync(ciphertext);
        await writer.DisposeAsync();

        Assert.Equal(plaintext, inner.ToArray());
    }

    [Fact]
    public async Task WriteAsync_WrongIdentity_FaultsWithoutMaskingAtDispose()
    {
        // The async mirror of the fault guard: DisposeAsync must not finalize a
        // stream that already threw, or the caller sees a truncation complaint
        // instead of the real error.
        using var identity = X25519Identity.Generate();
        using var stranger = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var output = new MemoryStream();
        var writer = Age.DecryptWriter(output, [stranger]);

        await Assert.ThrowsAsync<NoIdentityMatchException>(async () => await writer.WriteAsync(ciphertext));
        await writer.DisposeAsync();
    }

    [Fact]
    public async Task DisposeAsync_IsIdempotent()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var output = new MemoryStream();
        var writer = Age.DecryptWriter(output, [identity]);
        await writer.WriteAsync(ciphertext);

        await writer.DisposeAsync();
        await writer.DisposeAsync();
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(Pattern(100), [identity.Recipient]);

        using var output = new MemoryStream();
        var writer = Age.DecryptWriter(output, [identity]);
        writer.Write(ciphertext);

        writer.Dispose();
        writer.Dispose();
    }

    // --- every overload resolves ---------------------------------------------

    [Fact]
    public void EveryOverloadRoundTrips()
    {
        using var identity = X25519Identity.Generate();
        List<IIdentity> identityList = [identity];
        var options = new AgeDecryptOptions();
        var plaintext = Pattern(64);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        Check(output => Age.DecryptWriter(output, [identity]));
        Check(output => Age.DecryptWriter(output, [identity], options));
        Check(output => Age.DecryptWriter(output, identityList));
        Check(output => Age.DecryptWriter(output, identityList, options));

        void Check(Func<Stream, Stream> open)
        {
            using var output = new MemoryStream();
            using (var writer = open(output))
            {
                writer.Write(ciphertext);
            }

            Assert.Equal(plaintext, output.ToArray());
        }
    }

    [Fact]
    public void EmptyPlaintext_TouchesTheDestination()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(ReadOnlySpan<byte>.Empty, [identity.Recipient]);
        var destination = new TouchRecorder();

        using (var writer = Age.DecryptWriter(destination, [identity]))
        {
            writer.Write(ciphertext);
        }

        Assert.True(destination.Touched);
    }

    [Fact]
    public async Task EmptyPlaintext_TouchesTheDestination_Async()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(ReadOnlySpan<byte>.Empty, [identity.Recipient]);
        var destination = new TouchRecorder();

        await using (var writer = Age.DecryptWriter(destination, [identity]))
        {
            await writer.WriteAsync(ciphertext);
        }

        Assert.True(destination.Touched);
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

    private sealed class DisposeTrackingStream(Stream inner) : Stream
    {
        public bool WasDisposed { get; private set; }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            inner.Write(buffer);
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return inner.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    // --- the empty-plaintext destination write --------------------------------

    // A destination that only materializes on first write (a lazy file handle, say)
    // needs to be touched even when the plaintext is empty, or decrypting an empty
    // age file silently produces nothing at all. Sync and async must agree.
    private sealed class TouchRecorder : Stream
    {
        public bool Touched { get; private set; }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => 0;

        public override long Position
        {
            get => 0;
            set { }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Touched = true;
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Touched = true;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Touched = true;
            return ValueTask.CompletedTask;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
    }
}