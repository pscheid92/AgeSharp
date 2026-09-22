using System.Text;
using Age.Crypto;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Decrypted plaintext may only pass through buffers the library clears. Stream's own
/// <see cref="Stream.CopyTo(Stream)"/> and <see cref="Stream.CopyToAsync(Stream)"/> copy through a
/// pooled buffer and return it to <c>ArrayPool.Shared</c> uncleared, where the next renter
/// anywhere in the process receives the plaintext — so every plaintext stream copies its own way.
/// </summary>
public class PlaintextResidueTests
{
    private static readonly byte[] Marker = Encoding.ASCII.GetBytes("PLAINTEXT-RESIDUE-MARKER");

    [Fact]
    public void Decrypt_LeavesNoPlaintextInTheBuffersItWritesFrom()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(MarkedPlaintext(), identity.Recipient);

        var destination = new RecordingStream();
        AgeEncrypt.Decrypt(new MemoryStream(ciphertext), destination, identity);

        Assert.Equal(MarkedPlaintext(), destination.Received);
        Assert.DoesNotContain(destination.SourceArrays, HoldsPlaintext);
    }

    [Fact]
    public void DecryptDetached_LeavesNoPlaintextInTheBuffersItWritesFrom()
    {
        using var identity = X25519Identity.Generate();
        using var header = new MemoryStream();
        using var payload = new MemoryStream();
        AgeEncrypt.EncryptDetached(new MemoryStream(MarkedPlaintext()), header, payload, identity.Recipient);
        header.Position = 0;
        payload.Position = 0;

        var destination = new RecordingStream();
        AgeEncrypt.DecryptDetached(header, payload, destination, identity);

        Assert.Equal(MarkedPlaintext(), destination.Received);
        Assert.DoesNotContain(destination.SourceArrays, HoldsPlaintext);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DecryptReader_Copy_LeavesNoPlaintextInTheBuffersItWritesFrom(bool async)
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(MarkedPlaintext(), identity.Recipient);

        var destination = new RecordingStream();
        using (var decrypted = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identity))
            await Copy(decrypted, destination, async);

        Assert.Equal(MarkedPlaintext(), destination.Received);
        Assert.DoesNotContain(destination.SourceArrays, HoldsPlaintext);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DecryptReader_Copy_AfterPartialRead_DeliversTheRest(bool async)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MarkedPlaintext();
        using var decrypted = AgeEncrypt.DecryptReader(new MemoryStream(Encrypt(plaintext, identity.Recipient)), identity);

        var head = new byte[10];
        decrypted.ReadExactly(head);

        var destination = new RecordingStream();
        await Copy(decrypted, destination, async);

        Assert.Equal(plaintext[..10], head);
        Assert.Equal(plaintext[10..], destination.Received);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DecryptReader_Copy_AfterFailedRead_RethrowsTheFailure(bool async)
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(MarkedPlaintext(), identity.Recipient);

        // Corrupt chunk 0, the one the first ReadByte decrypts. 16 is the payload nonce.
        var payloadStart = (int)AgeHeader.Parse(new MemoryStream(ciphertext)).PayloadOffset + 16;
        ciphertext[payloadStart] ^= 0x01;

        using var decrypted = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identity);

        var first = Assert.Throws<AgePayloadException>(() => decrypted.ReadByte());
        var copy = await Assert.ThrowsAsync<AgePayloadException>(() => Copy(decrypted, new RecordingStream(), async));

        Assert.Same(first, copy);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RandomAccess_Copy_LeavesNoPlaintextInTheBuffersItWritesFrom(bool async)
    {
        using var identity = X25519Identity.Generate();
        using var reader = new AgeRandomAccess(new MemoryStream(Encrypt(MarkedPlaintext(), identity.Recipient)), identity);

        var destination = new RecordingStream();
        await Copy(reader.GetStream(), destination, async);

        Assert.Equal(MarkedPlaintext(), destination.Received);
        Assert.DoesNotContain(destination.SourceArrays, HoldsPlaintext);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RandomAccess_Copy_FromMidChunk_DeliversTheRestAndEndsAtTheEnd(bool async)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MarkedPlaintext();
        using var reader = new AgeRandomAccess(new MemoryStream(Encrypt(plaintext, identity.Recipient)), identity);

        const int start = StreamEncryption.ChunkSize + 123;
        using var stream = reader.GetStream(start);

        var destination = new RecordingStream();
        await Copy(stream, destination, async);

        Assert.Equal(plaintext[start..], destination.Received);
        Assert.Equal(stream.Length, stream.Position);
    }

    private static Task Copy(Stream source, Stream destination, bool async)
    {
        if (async)
            return source.CopyToAsync(destination);

        source.CopyTo(destination);
        return Task.CompletedTask;
    }

    // Spans more than two chunks, so the final chunk is short and every chunk is marked.
    private static byte[] MarkedPlaintext()
    {
        var plaintext = new byte[2 * StreamEncryption.ChunkSize + 1000];
        for (var i = 0; i + Marker.Length <= plaintext.Length; i += Marker.Length)
            Marker.CopyTo(plaintext, i);
        return plaintext;
    }

    private static byte[] Encrypt(byte[] plaintext, IRecipient recipient)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(plaintext), output, recipient);
        return output.ToArray();
    }

    private static bool HoldsPlaintext(byte[] array) =>
        array.AsSpan().IndexOf(Marker) >= 0;

    /// <summary>
    /// A destination that, like many hand-written streams, overrides only the array overload of
    /// Write — so span and async writes reach it through Stream's own plumbing and are recorded
    /// too. Keeps a reference to every array it was handed, to inspect once copying is over.
    /// </summary>
    private sealed class RecordingStream : Stream
    {
        private readonly MemoryStream _received = new();

        public List<byte[]> SourceArrays { get; } = [];
        public byte[] Received => _received.ToArray();

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (SourceArrays)
            {
                if (!SourceArrays.Contains(buffer))
                    SourceArrays.Add(buffer);

                _received.Write(buffer, offset, count);
            }
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
