using System.Text;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Tests for the asynchronous surface: <see cref="Age.EncryptAsync" />,
///     <see cref="Age.DecryptAsync" />, <see cref="Age.DecryptReaderAsync" />, and the
///     <c>ReadAsync</c>/<c>WriteAsync</c>/<c>DisposeAsync</c> stream overrides. The
///     central guarantee — no blocking I/O anywhere on the async paths — is pinned by
///     running full round-trips through <see cref="ThrowOnSyncIoStream" />.
/// </summary>
public class AsyncTests
{
    private static byte[] MakePlaintext(int size)
    {
        var data = new byte[size];
        for (var i = 0; i < size; i++)
            data[i] = (byte)((i * 31 + 7) & 0xFF);
        return data;
    }

    // --- The purity harness must actually reject synchronous I/O ---

    [Fact]
    public void ThrowOnSyncIoStream_RejectsEverySyncOperation()
    {
        using var s = new ThrowOnSyncIoStream(new MemoryStream(new byte[16]));

        Assert.Throws<InvalidOperationException>(() => s.Read(new byte[1], 0, 1));
        Assert.Throws<InvalidOperationException>(() => _ = s.Read(new byte[1].AsSpan()));
        Assert.Throws<InvalidOperationException>(() => s.ReadByte());
        Assert.Throws<InvalidOperationException>(() => s.Write(new byte[1], 0, 1));
        Assert.Throws<InvalidOperationException>(() => s.Flush());
    }

    // --- Purity: full round-trips through the throw-on-sync-IO harness ---

    private static async Task<byte[]> EncryptAsyncThroughHarness(byte[] plaintext, bool armored,
        params IRecipient[] recipients)
    {
        var output = new MemoryStream();
        await Age.EncryptAsync(new ThrowOnSyncIoStream(new MemoryStream(plaintext)), new ThrowOnSyncIoStream(output),
            recipients, new AgeEncryptOptions { Armor = armored });
        return output.ToArray();
    }

    private static async Task<byte[]> DecryptAsyncThroughHarness(byte[] ciphertext, params IIdentity[] identities)
    {
        var output = new MemoryStream();
        await Age.DecryptAsync(new ThrowOnSyncIoStream(new MemoryStream(ciphertext)), new ThrowOnSyncIoStream(output),
            identities);
        return output.ToArray();
    }

    private static async Task<byte[]> EncryptWriterThroughHarness(byte[] plaintext, bool armored,
        params IRecipient[] recipients)
    {
        var output = new MemoryStream();
        await using (var stream = Age.EncryptWriter(new ThrowOnSyncIoStream(output), recipients, new AgeEncryptOptions { Armor = armored }))
        {
            await stream.WriteAsync(plaintext);
        }

        return output.ToArray();
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65536, false)]
    [InlineData(131073, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65536, true)]
    [InlineData(131073, true)]
    public async Task EncryptAsync_Purity_RoundTrip(int size, bool armored)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = await EncryptAsyncThroughHarness(plaintext, armored, identity.Recipient);

        Assert.Equal(plaintext, Age.Decrypt(ciphertext, [identity]));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65536, false)]
    [InlineData(131073, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65536, true)]
    [InlineData(131073, true)]
    public async Task DecryptAsync_Purity_RoundTrip(int size, bool armored)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = armored });

        Assert.Equal(plaintext, await DecryptAsyncThroughHarness(ciphertext, identity));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(131073, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(131073, true)]
    public async Task EncryptWriter_WriteAsync_Purity_RoundTrip(int size, bool armored)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = await EncryptWriterThroughHarness(plaintext, armored, identity.Recipient);

        Assert.Equal(plaintext, Age.Decrypt(ciphertext, [identity]));
    }

    [Fact]
    public async Task DecryptReader_Seekable_CopyToAsync_UsesAsyncPath()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(200_000); // several chunks
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        // Sync DecryptReader over a seekable source returns the seekable decrypt stream;
        // copying it asynchronously exercises that stream's ReadAsync/DisposeAsync.
        await using var stream = Age.DecryptReader(new MemoryStream(ciphertext), [identity]);
        using var output = new MemoryStream();
        await stream.CopyToAsync(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task ForwardOnlyDecryptStream_UnsupportedMembers_Throw()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt("data"u8.ToArray(), [identity.Recipient]);

        // A non-seekable source is what yields the forward-only stream now.
        await using var stream = await Age.DecryptReaderAsync(
            new NonSeekableStream(new MemoryStream(ciphertext)), [identity]);

        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => _ = stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        stream.Flush(); // no-op
    }

    // --- Cross-path: async and sync interoperate both directions ---

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EncryptAsync_Then_SyncDecrypt(bool armored)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(70_000);

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        await Age.EncryptAsync(input, ciphertext, [identity.Recipient], new AgeEncryptOptions { Armor = armored });

        Assert.Equal(plaintext, Age.Decrypt(ciphertext.ToArray(), [identity]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SyncEncrypt_Then_DecryptAsync(bool armored)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(70_000);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient], new AgeEncryptOptions { Armor = armored });

        using var input = new MemoryStream(ciphertext);
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity]);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task MultipleRecipients_EachIdentityDecryptsAsync()
    {
        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        var plaintext = MakePlaintext(4096);
        var ciphertext = await EncryptAsyncThroughHarness(plaintext, false, a.Recipient, b.Recipient);

        Assert.Equal(plaintext, await DecryptAsyncThroughHarness(ciphertext, a));
        Assert.Equal(plaintext, await DecryptAsyncThroughHarness(ciphertext, b));
    }

    // --- DecryptReaderAsync shape and validation ---

    [Fact]
    public async Task DecryptReaderAsync_MirrorsTheSourcesSeekability()
    {
        // DecryptReaderAsync used to return a forward-only stream unconditionally, so the
        // same source seeked synchronously but not asynchronously. It now runs the
        // same dispatch as DecryptReader.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(5).NextBytes(plaintext);
        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        await using (var seekable = await Age.DecryptReaderAsync(new MemoryStream(ciphertext), [identity]))
        {
            Assert.True(seekable.CanSeek);
            Assert.Equal(plaintext.Length, seekable.Length);

            seekable.Seek(60_000, SeekOrigin.Begin);
            var buffer = new byte[64];
            await seekable.ReadExactlyAsync(buffer);
            Assert.Equal(plaintext.AsSpan(60_000, 64).ToArray(), buffer);
        }

        await using var forwardOnly = await Age.DecryptReaderAsync(
            new NonSeekableStream(new MemoryStream(ciphertext)), [identity]);

        Assert.True(forwardOnly.CanRead);
        Assert.False(forwardOnly.CanSeek);
    }

    [Fact]
    public async Task EncryptAsync_NoRecipients_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Age.EncryptAsync(new MemoryStream(), new MemoryStream(), []));
    }

    [Fact]
    public async Task DecryptAsync_NoIdentities_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Age.DecryptAsync(new MemoryStream(), new MemoryStream(), []));
    }

    [Fact]
    public async Task DecryptReaderAsync_NoIdentities_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(async () => await Age.DecryptReaderAsync(new MemoryStream(), []));
    }

    [Fact]
    public async Task DecryptAsync_WrongIdentity_Throws()
    {
        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        var ciphertext = Age.Encrypt("secret"u8.ToArray(), [a.Recipient]);

        await Assert.ThrowsAsync<NoIdentityMatchException>(() => DecryptAsyncThroughHarness(ciphertext, b));
    }

    // --- Cancellation: mid-header and mid-chunk both surface as cancellation ---

    [Fact]
    public async Task DecryptAsync_CancelledMidHeader_Throws()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(MakePlaintext(100_000), [identity.Recipient]);

        using var cts = new CancellationTokenSource();
        var source = new CancelAfterStream(new MemoryStream(ciphertext), cts, 8); // within the header
        using var output = new MemoryStream();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Age.DecryptAsync(source, output, [identity], cancellationToken: cts.Token));
    }

    [Fact]
    public async Task DecryptAsync_CancelledMidChunk_Throws()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(MakePlaintext(200_000), [identity.Recipient]); // several chunks

        using var cts = new CancellationTokenSource();
        var source = new CancelAfterStream(new MemoryStream(ciphertext), cts, 70_000); // deep in the payload
        using var output = new MemoryStream();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Age.DecryptAsync(source, output, [identity], cancellationToken: cts.Token));
    }

    // --- The byte[] ReadAsync/WriteAsync overloads, FlushAsync, double DisposeAsync ---

    [Fact]
    public async Task AsyncByteArrayOverloads_And_Flush_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(200_000);

        // Push writer: WriteAsync(byte[], offset, count) + FlushAsync (binary).
        var pushOut = new MemoryStream();
        await using (var writer = Age.EncryptWriter(pushOut, [identity.Recipient]))
        {
            await writer.WriteAsync(plaintext, 0, plaintext.Length);
            await writer.FlushAsync();
        }

        Assert.Equal(plaintext, Age.Decrypt(pushOut.ToArray(), [identity]));

        // Push armor writer directly: WriteAsync(byte[], ...) + FlushAsync.
        var armorOut = new MemoryStream();
        await using (var armorWriter = new ArmorWriterStream(armorOut))
        {
            await armorWriter.WriteAsync(new byte[48], 0, 48);
            await armorWriter.FlushAsync();
        }

        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", Encoding.ASCII.GetString(armorOut.ToArray()));

        // Pull readers: ReadAsync(byte[], offset, count) — binary (EncryptStream) and armored (ArmorStream).
        Assert.Equal(plaintext,
            await ReadAllByteArrayAsync(Age.EncryptReader(new MemoryStream(plaintext), [identity.Recipient]), identity));
        Assert.Equal(plaintext,
            await ReadAllByteArrayAsync(
                Age.EncryptReader(new MemoryStream(plaintext), [identity.Recipient], new AgeEncryptOptions { Armor = true }), identity, true));

        var ciphertext = Age.Encrypt(plaintext, [identity.Recipient]);

        // Decrypt readers: ReadAsync(byte[], ...) — seekable (DecryptReader) and forward-only (DecryptReaderAsync).
        await using (var seekable = Age.DecryptReader(new MemoryStream(ciphertext), [identity]))
        {
            Assert.Equal(plaintext, await DrainByteArrayAsync(seekable));
        }

        await using (var forward = await Age.DecryptReaderAsync(new MemoryStream(ciphertext), [identity]))
        {
            Assert.Equal(plaintext, await DrainByteArrayAsync(forward));
        }
    }

    [Fact]
    public async Task EncryptWriter_DoubleDisposeAsync_IsNoOp()
    {
        using var identity = X25519Identity.Generate();
        var output = new MemoryStream();

        var stream = Age.EncryptWriter(output, [identity.Recipient]);
        await stream.WriteAsync(new byte[] { 1, 2, 3 });
        await stream.DisposeAsync();
        var afterFirst = output.ToArray();
        await stream.DisposeAsync(); // second async dispose is a no-op

        Assert.Equal(afterFirst, output.ToArray());
        Assert.Equal(new byte[] { 1, 2, 3 }, Age.Decrypt(afterFirst, [identity]));
    }

    // --- Async error paths ---

    [Fact]
    public async Task DecryptReaderAsync_TruncatedHeader_Throws()
    {
        using var identity = X25519Identity.Generate();
        var bytes = Encoding.ASCII.GetBytes("age-encryption.org/v1\n"); // no MAC line

        await Assert.ThrowsAsync<AgeFormatException>(async () =>
            await Age.DecryptReaderAsync(new MemoryStream(bytes), [identity]));
    }

    [Fact]
    public async Task DecryptReaderAsync_MissingNonce_Throws()
    {
        using var identity = X25519Identity.Generate();
        var full = Age.Encrypt("data"u8.ToArray(), [identity.Recipient]);
        var headerOnly = full[..(int)Age.ReadHeader(new MemoryStream(full)).PayloadOffset]; // header, no nonce

        await Assert.ThrowsAsync<AgeFormatException>(async () =>
            await Age.DecryptReaderAsync(new MemoryStream(headerOnly), [identity]));
    }

    [Fact]
    public async Task DecryptAsync_ForwardOnly_EmptyPayload_Throws()
    {
        using var identity = X25519Identity.Generate();
        var full = Age.Encrypt("data"u8.ToArray(), [identity.Recipient]);
        var offset = (int)Age.ReadHeader(new MemoryStream(full)).PayloadOffset;
        var headerAndNonce = full[..(offset + 16)]; // header + nonce, zero chunks

        // Non-seekable forces the forward-only decrypt path.
        using var source = new NonSeekableStream(new MemoryStream(headerAndNonce));
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<AgeAuthenticationException>(() => Age.DecryptAsync(source, output, [identity]));
    }

    private static async Task<byte[]> ReadAllByteArrayAsync(Stream ciphertextStream, IIdentity identity,
        bool decodeCiphertext = false)
    {
        var ciphertext = new MemoryStream();
        await using (ciphertextStream)
        {
            var buffer = new byte[8192];
            int n;
            while ((n = await ciphertextStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                ciphertext.Write(buffer, 0, n);
        }

        // decodeCiphertext is irrelevant to the read path; both binary and armored
        // ciphertext decrypt through the sync facade for verification.
        _ = decodeCiphertext;
        return Age.Decrypt(ciphertext.ToArray(), [identity]);
    }

    private static async Task<byte[]> DrainByteArrayAsync(Stream plaintextStream)
    {
        var output = new MemoryStream();
        var buffer = new byte[8192];
        int n;
        while ((n = await plaintextStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            output.Write(buffer, 0, n);
        return output.ToArray();
    }

    // --- Interop: async encryption decrypts with the reference age CLI ---

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EncryptAsync_DecryptWithAge(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(70_000);
        var ciphertext = await EncryptAsyncThroughHarness(plaintext, armored, identity.Recipient);

        Assert.Equal(plaintext, AgeCli.Decrypt(identity.ToSecretString(), ciphertext));
    }

    /// <summary>
    ///     A forward-only async stream that cancels the given token once a threshold of
    ///     bytes has been read, so a decrypt can be interrupted mid-header or mid-chunk.
    /// </summary>
    private sealed class CancelAfterStream(Stream inner, CancellationTokenSource cts, long cancelAfter) : Stream
    {
        private long _read;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            _read += read;
            if (_read >= cancelAfter)
                cts.Cancel();
            return read;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
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