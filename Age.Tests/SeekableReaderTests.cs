using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// What <c>DecryptReader</c> returns for a binary file on a seekable stream: plaintext readable
/// from any position, with a length the final chunk authenticates, read synchronously or not.
/// </summary>
public class SeekableReaderTests
{
    private const int Chunk = StreamEncryption.ChunkSize;
    private static readonly byte[] Plaintext = Enumerable.Range(0, 3 * Chunk + 100).Select(i => (byte)(i * 31 + 7)).ToArray();

    [Fact]
    public void ReadsFromAnyPosition()
    {
        using var alice = X25519Identity.Generate();
        using var reader = Open(alice, Plaintext);

        foreach (var at in new long[] { 3 * Chunk + 50, 0, Chunk - 3, 2 * Chunk, Chunk - 3 })
        {
            reader.Position = at;
            var buffer = new byte[100];
            var read = reader.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);

            Assert.Equal(Plaintext.AsSpan((int)at, read).ToArray(), buffer[..read]);
            Assert.Equal(at + read, reader.Position);
        }
    }

    [Fact]
    public void SeekingFromEachOrigin()
    {
        using var alice = X25519Identity.Generate();
        using var reader = Open(alice, Plaintext);

        Assert.Equal(10, reader.Seek(10, SeekOrigin.Begin));
        Assert.Equal(15, reader.Seek(5, SeekOrigin.Current));
        Assert.Equal(Plaintext.Length - 1, reader.Seek(-1, SeekOrigin.End));
        Assert.Equal(Plaintext[^1], reader.ReadByte());
        Assert.Equal(-1, reader.ReadByte());

        Assert.Throws<ArgumentOutOfRangeException>(() => reader.Seek(-1, SeekOrigin.Begin));
        Assert.Throws<ArgumentOutOfRangeException>(() => reader.Seek(0, (SeekOrigin)7));
        Assert.Throws<ArgumentOutOfRangeException>(() => reader.Position = -1);
    }

    [Fact]
    public void PastTheEnd_ReadsNothing()
    {
        using var alice = X25519Identity.Generate();
        using var reader = Open(alice, Plaintext);

        reader.Position = Plaintext.Length + 10;

        Assert.Equal(0, reader.Read(new byte[10]));
        reader.CopyTo(Stream.Null);
        Assert.Equal(Plaintext.Length + 10, reader.Position);
    }

    [Fact]
    public async Task ReadsAsynchronously_WithoutAnySynchronousRead()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        await using var reader = await new Identities(alice).DecryptReaderAsync(new SeekableAsyncOnlyStream(file));
        Assert.Equal(Plaintext.Length, reader.Length);

        reader.Position = Chunk + 5;
        var buffer = new byte[Chunk];
        Assert.Equal(buffer.Length, await reader.ReadAtLeastAsync(buffer, buffer.Length));
        Assert.Equal(Plaintext.AsSpan(Chunk + 5, Chunk).ToArray(), buffer);

        reader.Position = 0;
        var output = new MemoryStream();
        await reader.CopyToAsync(new AsyncOnlyStream(output));
        Assert.Equal(Plaintext, output.ToArray());

        reader.Position = 3;
        Assert.Equal(4, await reader.ReadAsync(buffer, 0, 4, CancellationToken.None));
        Assert.Equal(Plaintext[3..7], buffer[..4]);
    }

    [Fact]
    public void TheFinalChunk_IsAuthenticatedWhenOpening()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        file[^1] ^= 1;

        Assert.Throws<AgePayloadException>(() => new Identities(alice).DecryptReader(new MemoryStream(file)));
    }

    [Fact]
    public async Task TheFinalChunk_IsAuthenticatedWhenOpening_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        file[^1] ^= 1;

        await Assert.ThrowsAsync<AgePayloadException>(async () => await new Identities(alice).DecryptReaderAsync(new MemoryStream(file)));
    }

    [Fact]
    public void AnEmptyPayload_IsRefusedWhenOpening()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var headerAndNonce = (int)AgeHeader.Read(new MemoryStream(file)).PayloadOffset!.Value + StreamEncryption.PayloadNonceSize;

        var ex = Assert.Throws<AgePayloadException>(() => new Identities(alice).DecryptReader(new MemoryStream(file[..headerAndNonce])));
        Assert.Contains("payload is empty", ex.Message, StringComparison.Ordinal);
    }

    // Boundaries follow from the position, so a failed read is not final: it leaves the position
    // where it was, and a retry reads the same chunk again. Nothing of the failed read is lost.
    [Fact]
    public void AFailedRead_LeavesThePositionWhereItWas()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var payloadStart = (int)AgeHeader.Read(new MemoryStream(file)).PayloadOffset!.Value + StreamEncryption.PayloadNonceSize;
        file[payloadStart + StreamEncryption.EncryptedChunkSize + 3] ^= 1;

        using var reader = new Identities(alice).DecryptReader(new MemoryStream(file));
        reader.Position = Chunk - 10;

        Assert.Throws<AgePayloadException>(() => reader.Read(new byte[100]));
        Assert.Equal(Chunk - 10, reader.Position);
        Assert.Throws<AgePayloadException>(() => reader.Read(new byte[100]));

        reader.Position = 2 * Chunk;
        Assert.Equal(100, reader.Read(new byte[100]));
    }

    [Fact]
    public async Task AFailedAsyncRead_LeavesThePositionWhereItWas()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var payloadStart = (int)AgeHeader.Read(new MemoryStream(file)).PayloadOffset!.Value + StreamEncryption.PayloadNonceSize;
        file[payloadStart + 3] ^= 1;

        using var reader = new Identities(alice).DecryptReader(new MemoryStream(file));
        reader.Position = 7;

        await Assert.ThrowsAsync<AgePayloadException>(async () => await reader.ReadAtLeastAsync(new byte[100], 100));
        Assert.Equal(7, reader.Position);
    }

    [Fact]
    public void AFileThatShrankUnderneath_IsAPayloadError()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var stream = new MemoryStream();
        stream.Write(file);
        stream.Position = 0;

        using var reader = new Identities(alice).DecryptReader(stream);
        stream.SetLength(stream.Length - StreamEncryption.EncryptedChunkSize);
        reader.Position = 2 * Chunk;

        Assert.Throws<AgePayloadException>(() => reader.Read(new byte[10]));
    }

    [Fact]
    public async Task AFileThatShrankUnderneath_IsAPayloadError_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var stream = new MemoryStream();
        stream.Write(file);
        stream.Position = 0;

        using var reader = new Identities(alice).DecryptReader(stream);
        stream.SetLength(stream.Length - StreamEncryption.EncryptedChunkSize);
        reader.Position = 2 * Chunk;

        await Assert.ThrowsAsync<AgePayloadException>(async () => await reader.ReadAtLeastAsync(new byte[10], 10));
    }

    [Fact]
    public void RequiringArmor_RefusesASeekableBinaryFile()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var options = new AgeDecryptOptions { RequireArmor = true };

        Assert.Throws<AgeArmorException>(() => new Identities(alice).DecryptReader(new MemoryStream(file), options));
    }

    [Fact]
    public async Task RequiringArmor_RefusesASeekableBinaryFile_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var options = new AgeDecryptOptions { RequireArmor = true };

        await Assert.ThrowsAsync<AgeArmorException>(async () => await new Identities(alice).DecryptReaderAsync(new MemoryStream(file), options));
    }

    [Fact]
    public void ADisposedReader_ReadsNoMore_AndLeavesTheStreamOpen()
    {
        using var alice = X25519Identity.Generate();
        var stream = new MemoryStream(new Recipients(alice.Recipient).Encrypt(Plaintext));
        var reader = new Identities(alice).DecryptReader(stream);

        reader.Dispose();
        reader.Dispose();

        Assert.False(reader.CanRead);
        Assert.False(reader.CanSeek);
        Assert.False(reader.CanWrite);
        Assert.Throws<ObjectDisposedException>(() => reader.Length);
        Assert.Throws<ObjectDisposedException>(() => reader.Position);
        Assert.Throws<ObjectDisposedException>(() => reader.Position = 0);
        Assert.Throws<ObjectDisposedException>(() => reader.Seek(0, SeekOrigin.Begin));
        Assert.Throws<ObjectDisposedException>(() => reader.Read(new byte[1]));
        Assert.Throws<ObjectDisposedException>(() => reader.CopyTo(Stream.Null));
        Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task ADisposedReader_ReadsNoMore_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var reader = new Identities(alice).DecryptReader(new MemoryStream(new Recipients(alice.Recipient).Encrypt(Plaintext)));
        await reader.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await reader.ReadAtLeastAsync(new byte[1], 1));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => reader.CopyToAsync(Stream.Null));
    }

    [Fact]
    public void ItOnlyReads()
    {
        using var alice = X25519Identity.Generate();
        using var reader = Open(alice, Plaintext);

        reader.Flush();
        Assert.Throws<NotSupportedException>(() => reader.SetLength(0));
        Assert.Throws<NotSupportedException>(() => reader.Write([1], 0, 1));
    }

    private static Stream Open(X25519Identity identity, byte[] plaintext) =>
        new Identities(identity).DecryptReader(new MemoryStream(new Recipients(identity.Recipient).Encrypt(plaintext)));

    // Seekable, but throws on every synchronous read.
    private sealed class SeekableAsyncOnlyStream(byte[] data) : Stream
    {
        private readonly MemoryStream _inner = new(data);

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("synchronous read");
        public override int Read(Span<byte> buffer) => throw new InvalidOperationException("synchronous read");
        public override int ReadByte() => throw new InvalidOperationException("synchronous read");

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
