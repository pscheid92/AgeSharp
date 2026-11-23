using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The push forms: what is written to an encrypt writer reaches the destination as an age file,
/// and an age file written to a decrypt writer reaches it as plaintext. Disposing ends the input.
/// Both stop for good at the first failure.
/// </summary>
public class WriterTests
{
    private const int Chunk = StreamEncryption.ChunkSize;

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(Chunk, false)]
    [InlineData(Chunk + 1, false)]
    [InlineData(2 * Chunk, false)]
    [InlineData(0, true)]
    [InlineData(Chunk, true)]
    [InlineData(2 * Chunk + 7, true)]
    public void WhatIsWritten_RoundTrips(int size, bool armor)
    {
        using var alice = X25519Identity.Generate();
        var plaintext = Plaintext(size);
        var file = new MemoryStream();

        using (var writer = new Recipients(alice.Recipient).EncryptWriter(file, new AgeEncryptOptions { Armor = armor }))
            WriteInPieces(writer, plaintext, 1000);

        var output = new MemoryStream();
        using (var writer = new Identities(alice).DecryptWriter(output))
            WriteInPieces(writer, file.ToArray(), 777);

        Assert.Equal(plaintext, output.ToArray());
        Assert.Equal(plaintext, new Identities(alice).Decrypt(file.ToArray()));
    }

    // The writer's file is the reader's, armor lines and all: only the random parts differ, so
    // the same binary armors to the same text either way.
    [Theory]
    [InlineData(0)]
    [InlineData(47)]
    [InlineData(48)]
    [InlineData(1000)]
    public void ArmorWritten_IsArmorRead(int size)
    {
        var binary = Plaintext(size);

        using var pulled = new MemoryStream();
        using (var reader = new ArmorStream(new MemoryStream(binary)))
            reader.CopyTo(pulled);

        using var pushed = new MemoryStream();
        var writer = new ArmorWriterStream(pushed);
        WriteInPieces(writer, binary, 5);
        writer.Finish();

        Assert.Equal(pulled.ToArray(), pushed.ToArray());
    }

    [Fact]
    public void TheArmorWriter_OnlyWrites()
    {
        var writer = new ArmorWriterStream(new MemoryStream());

        Assert.False(writer.CanRead);
        Assert.False(writer.CanSeek);
        Assert.True(writer.CanWrite);
        Assert.Throws<NotSupportedException>(() => writer.Length);
        Assert.Throws<NotSupportedException>(() => writer.Position);
        Assert.Throws<NotSupportedException>(() => writer.Position = 0);
        Assert.Throws<NotSupportedException>(() => writer.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => writer.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => writer.SetLength(0));
        writer.Flush();

        writer.Dispose();
        Assert.Throws<ObjectDisposedException>(() => writer.Write([1]));
    }

    [Fact]
    public async Task ArmorWrittenAsynchronously_IsArmorRead()
    {
        var binary = Plaintext(1000);

        using var pulled = new MemoryStream();
        using (var reader = new ArmorStream(new MemoryStream(binary)))
            reader.CopyTo(pulled);

        var pushed = new MemoryStream();
        var writer = new ArmorWriterStream(new AsyncOnlyStream(pushed));
        await writer.WriteAsync(binary.AsMemory(0, 100));
        await writer.WriteAsync(binary, 100, binary.Length - 100, CancellationToken.None);
        await writer.FlushAsync();
        await writer.FinishAsync(CancellationToken.None);

        Assert.Equal(pulled.ToArray(), pushed.ToArray());

        var empty = new MemoryStream();
        await new ArmorWriterStream(new AsyncOnlyStream(empty)).FinishAsync(CancellationToken.None);
        Assert.Equal("-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n"u8.ToArray(), empty.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BothWriters_NeverWriteSynchronously(bool armor)
    {
        using var alice = X25519Identity.Generate();
        var plaintext = Plaintext(3 * Chunk + 5);
        var file = new MemoryStream();

        await using (var writer = new Recipients(alice.Recipient).EncryptWriter(new AsyncOnlyStream(file), new AgeEncryptOptions { Armor = armor }))
        {
            await writer.WriteAsync(plaintext.AsMemory(0, 10));
            await writer.WriteAsync(plaintext, 10, plaintext.Length - 10, CancellationToken.None);
            await writer.FlushAsync();
        }

        var output = new MemoryStream();
        await using (var writer = new Identities(alice).DecryptWriter(new AsyncOnlyStream(output)))
        {
            var bytes = file.ToArray();
            await writer.WriteAsync(bytes.AsMemory(0, 100));
            await writer.WriteAsync(bytes, 100, bytes.Length - 100, CancellationToken.None);
            await writer.FlushAsync();
        }

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void TheEncryptWriter_WritesNothingUntilWrittenTo()
    {
        using var alice = X25519Identity.Generate();
        var file = new MemoryStream();

        var writer = new Recipients(alice.Recipient).EncryptWriter(file);
        Assert.Equal(0, file.Length);

        writer.Dispose();
        writer.Dispose();
        Assert.Equal([], new Identities(alice).Decrypt(file.ToArray()));
    }

    [Fact]
    public void TheEncryptWriter_RefusesMixedLabelsBeforeWritingAnything()
    {
        using var classical = X25519Identity.Generate();
        using var postQuantum = MlKem768X25519Identity.Generate();
        var file = new MemoryStream();

        Assert.Throws<AgeException>(() => new Recipients(classical.Recipient, postQuantum.Recipient).EncryptWriter(file));
        Assert.Equal(0, file.Length);
    }

    [Fact]
    public void TheDestinations_AreLeftOpen()
    {
        using var alice = X25519Identity.Generate();
        var file = new MemoryStream();
        var output = new MemoryStream();

        new Recipients(alice.Recipient).EncryptWriter(file).Dispose();
        using (var writer = new Identities(alice).DecryptWriter(output))
            writer.Write(file.ToArray());

        Assert.True(file.CanWrite);
        Assert.True(output.CanWrite);
    }

    [Fact]
    public void TheWriters_OnlyWrite()
    {
        using var alice = X25519Identity.Generate();

        foreach (var writer in new[] { new Recipients(alice.Recipient).EncryptWriter(new MemoryStream()), new Identities(alice).DecryptWriter(new MemoryStream()) })
        {
            Assert.False(writer.CanRead);
            Assert.False(writer.CanSeek);
            Assert.True(writer.CanWrite);
            Assert.Throws<NotSupportedException>(() => writer.Length);
            Assert.Throws<NotSupportedException>(() => writer.Position);
            Assert.Throws<NotSupportedException>(() => writer.Position = 0);
            Assert.Throws<NotSupportedException>(() => writer.Read(new byte[1], 0, 1));
            Assert.Throws<NotSupportedException>(() => writer.Seek(0, SeekOrigin.Begin));
            Assert.Throws<NotSupportedException>(() => writer.SetLength(0));
            writer.Flush();
        }
    }

    [Fact]
    public async Task AWriterDisposed_TakesNoMore()
    {
        using var alice = X25519Identity.Generate();
        var encrypting = new Recipients(alice.Recipient).EncryptWriter(new MemoryStream());
        var decrypting = new Identities(alice).DecryptWriter(new MemoryStream());
        encrypting.Dispose();
        await Assert.ThrowsAsync<AgeFormatException>(async () => await decrypting.DisposeAsync());

        foreach (var writer in new[] { encrypting, decrypting })
        {
            Assert.Throws<ObjectDisposedException>(() => writer.Write([1]));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await writer.WriteAsync(new byte[1]));
            Assert.Throws<ObjectDisposedException>(writer.Flush);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => writer.FlushAsync());
            await writer.DisposeAsync();
        }
    }

    // A failed write may have lost plaintext the destination never took; the file is not finished.
    [Fact]
    public void AfterTheDestinationFails_TheEncryptWriterKeepsFailing_AndFinishesNothing()
    {
        using var alice = X25519Identity.Generate();
        var destination = new FailingStream(failAt: 100);
        var writer = new Recipients(alice.Recipient).EncryptWriter(destination);

        var first = Assert.Throws<IOException>(() => writer.Write(Plaintext(3 * Chunk)));
        var retry = Assert.Throws<IOException>(() => writer.Write([1]));
        Assert.Same(first, retry);

        var written = destination.Written;
        writer.Dispose();
        Assert.Equal(written, destination.Written);
    }

    [Fact]
    public async Task AfterTheDestinationFails_TheEncryptWriterKeepsFailing_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var destination = new FailingStream(failAt: 100);
        var writer = new Recipients(alice.Recipient).EncryptWriter(destination, new AgeEncryptOptions { Armor = true });

        var first = await Assert.ThrowsAsync<IOException>(async () => await writer.WriteAsync(Plaintext(3 * Chunk)));
        var retry = await Assert.ThrowsAsync<IOException>(async () => await writer.WriteAsync(new byte[1]));
        Assert.Same(first, retry);

        var written = destination.Written;
        await writer.DisposeAsync();
        Assert.Equal(written, destination.Written);
    }

    [Fact]
    public void TheDecryptWriter_ReadsNothingUntilWrittenTo()
    {
        using var stranger = X25519Identity.Generate();
        var output = new MemoryStream();

        var writer = new Identities(stranger).DecryptWriter(output);

        Assert.Equal(0, output.Length);
        Assert.Throws<AgeFormatException>(writer.Dispose);
    }

    [Fact]
    public void ADecryptWriter_CanBeDisposedTwice()
    {
        using var alice = X25519Identity.Generate();
        var writer = new Identities(alice).DecryptWriter(new MemoryStream());
        writer.Write(new Recipients(alice.Recipient).Encrypt([1, 2, 3]));

        writer.Dispose();
        writer.Dispose();
    }

    // Armor cut off inside its body, with no newline after its last line, where that line would
    // complete a chunk: the missing end is reported before anything the line decodes to is used,
    // so nothing of that chunk is written, as when the same armor is read.
    [Fact]
    public void ArmorCutOffMidBody_EndsAsItDoesWhenRead()
    {
        using var alice = X25519Identity.Generate();
        var binary = new Recipients(alice.Recipient).Encrypt(Plaintext(2 * Chunk));
        var armored = System.Text.Encoding.ASCII.GetString(new Recipients(alice.Recipient).Encrypt(Plaintext(2 * Chunk), new AgeEncryptOptions { Armor = true }));

        // The binary byte that fills the held chunk, and the armor line it is on.
        var payloadStart = (int)AgeHeader.Read(new MemoryStream(binary)).PayloadOffset!.Value + StreamEncryption.PayloadNonceSize;
        var lines = armored.Split('\n');
        var line = 1 + (payloadStart + StreamEncryption.EncryptedChunkSize) / 48;
        var cut = System.Text.Encoding.ASCII.GetBytes(string.Join('\n', lines[..(line + 1)]));

        var readOutput = new MemoryStream();
        var read = Assert.ThrowsAny<AgeException>(() => new Identities(alice).Decrypt(new MemoryStream(cut), readOutput));

        var writtenOutput = new MemoryStream();
        var written = Assert.ThrowsAny<AgeException>(() =>
        {
            using var writer = new Identities(alice).DecryptWriter(writtenOutput);
            writer.Write(cut);
        });

        Assert.Equal(read.Message, written.Message);
        Assert.Equal(0, writtenOutput.Length);
        Assert.Equal(readOutput.ToArray(), writtenOutput.ToArray());
    }

    [Fact]
    public void ATruncatedFile_IsFoundOutWhenDisposing()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext(2 * Chunk + 10));
        var output = new MemoryStream();

        var writer = new Identities(alice).DecryptWriter(output);
        writer.Write(file.AsSpan(0, file.Length - 20));

        Assert.Throws<AgeAuthenticationException>(writer.Dispose);
    }

    [Fact]
    public async Task ATruncatedFile_IsFoundOutWhenDisposing_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext(2 * Chunk + 10), new AgeEncryptOptions { Armor = true });

        var writer = new Identities(alice).DecryptWriter(new MemoryStream());
        await writer.WriteAsync(file.AsMemory(0, file.Length / 2));

        await Assert.ThrowsAsync<AgeFormatException>(async () => await writer.DisposeAsync());
    }

    // After a chunk fails, the next chunk boundary is unknown: nothing more is taken or finished.
    [Fact]
    public void AfterAChunkFails_TheDecryptWriterKeepsFailing_AndFinishesNothing()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext(3 * Chunk));
        var payloadStart = (int)AgeHeader.Read(new MemoryStream(file)).PayloadOffset!.Value + StreamEncryption.PayloadNonceSize;
        file[payloadStart + 5] ^= 1;
        var output = new MemoryStream();

        var writer = new Identities(alice).DecryptWriter(output);
        var first = Assert.Throws<AgeAuthenticationException>(() => writer.Write(file));
        var retry = Assert.Throws<AgeAuthenticationException>(() => writer.Write([1]));
        Assert.Same(first, retry);

        writer.Dispose();
        Assert.Equal(0, output.Length);
    }

    // The chunks before it were written out as they authenticated; the final one fails at the end.
    [Fact]
    public async Task ACorruptFinalChunk_IsFoundOutWhenDisposing()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext(3 * Chunk));
        file[^5] ^= 1;
        var output = new MemoryStream();

        var writer = new Identities(alice).DecryptWriter(output);
        await writer.WriteAsync(file);

        await Assert.ThrowsAsync<AgeAuthenticationException>(async () => await writer.DisposeAsync());
        Assert.Equal(2 * Chunk, output.Length);
    }

    // A cancelled write may have handed the destination part of a chunk: it is a failure like any other.
    [Fact]
    public async Task ACancelledWrite_IsFinal()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext(3 * Chunk));
        var writer = new Identities(alice).DecryptWriter(new FailingStream(failAt: long.MaxValue));

        var first = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await writer.WriteAsync(file, new CancellationToken(canceled: true)));
        var retry = Assert.ThrowsAny<OperationCanceledException>(() => writer.Write([1]));

        Assert.Same(first, retry);
        writer.Dispose();
    }

    [Fact]
    public void AnEmptyPlaintext_StillReachesTheDestination()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt([]);
        var output = new FailingStream(failAt: long.MaxValue);

        using (var writer = new Identities(alice).DecryptWriter(output))
            writer.Write(file);

        Assert.Equal(1, output.Writes);
    }

    [Fact]
    public void RequiringArmor_IsHonoured()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext(10));
        var writer = new Identities(alice).DecryptWriter(new MemoryStream(), new AgeDecryptOptions { RequireArmor = true });

        Assert.Throws<AgeFormatException>(() => writer.Write(file));
    }

    [Fact]
    public void ADisposedSet_GivesNoWriter()
    {
        using var alice = X25519Identity.Generate();
        var set = Identities.Parse(alice.ToSecretString());
        set.Dispose();

        Assert.Throws<ObjectDisposedException>(() => set.DecryptWriter(new MemoryStream()));
    }

    // Whitespace before armor long enough to be looked at twice, then armor, written a byte at a time.
    [Fact]
    public void LeadingWhitespace_WrittenAByteAtATime()
    {
        using var alice = X25519Identity.Generate();
        var plaintext = Plaintext(100);
        byte[] file = [.. "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n  \n"u8,
            .. new Recipients(alice.Recipient).Encrypt(plaintext, new AgeEncryptOptions { Armor = true })];
        var output = new MemoryStream();

        using (var writer = new Identities(alice).DecryptWriter(output))
            WriteInPieces(writer, file, 1);

        Assert.Equal(plaintext, output.ToArray());
    }

    // A file shorter than the begin marker is decided only when the writer is disposed; what was
    // held to decide it must still be read, and fail as the reading side fails.
    [Theory]
    [InlineData("")]
    [InlineData("age")]
    [InlineData("age-encryption.org/v1\n")]
    [InlineData("age-encryption.org/v2\n")]
    [InlineData("\n\n  ")]
    [InlineData("-----BEGIN AGE")]
    public void AShortFile_FailsAsItDoesWhenRead(string text)
    {
        using var alice = X25519Identity.Generate();
        var file = System.Text.Encoding.ASCII.GetBytes(text);
        var with = new Identities(alice);

        var read = Assert.ThrowsAny<AgeException>(() => with.Decrypt(file));
        var written = Assert.ThrowsAny<AgeException>(() =>
        {
            using var writer = with.DecryptWriter(new MemoryStream());
            writer.Write(file);
        });

        Assert.Equal(read.GetType(), written.GetType());
        Assert.Equal(read.Message, written.Message);
    }

    // A begin line indented by 600,000 spaces once made the lookahead, with a raised line limit,
    // grow past a megabyte and hold whole chunks, which the writer then refused with a raw
    // exception the reader did not throw. An indented begin line is refused now, as go-age
    // refuses it: the reader and the writer refuse it alike, whether the file runs past the
    // lookahead or ends inside it.
    [Theory]
    [InlineData(512 * 1024)]
    [InlineData(200 * 1024)]
    public void AHugelyIndentedBeginLine_IsRefusedAlikeByReaderAndWriter(int length)
    {
        using var key = X25519Identity.Generate();
        var plaintext = Plaintext(length);
        var armored = System.Text.Encoding.ASCII.GetString(new Recipients(key.Recipient).Encrypt(plaintext, new AgeEncryptOptions { Armor = true }));
        var file = System.Text.Encoding.ASCII.GetBytes(new string(' ', 600_000) + armored);
        var options = new AgeDecryptOptions { MaxArmorLineBytes = 1024 * 1024 };
        var identities = new Identities(key);

        Assert.Throws<AgeFormatException>(() =>
        {
            using var reader = identities.DecryptReader(new MemoryStream(file), options);
            reader.CopyTo(Stream.Null);
        });

        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = identities.DecryptWriter(Stream.Null, options);
            WriteInPieces(writer, file, 64 * 1024);
        });

        _ = plaintext;
    }

    private static byte[] Plaintext(int length) =>
        Enumerable.Range(0, length).Select(i => (byte)(i * 13 + 1)).ToArray();

    private static void WriteInPieces(Stream writer, byte[] data, int piece)
    {
        for (var at = 0; at < data.Length; at += piece)
            writer.Write(data, at, Math.Min(piece, data.Length - at));
    }

    // Counts what reaches it, and fails the write that would take it past failAt.
    private sealed class FailingStream(long failAt) : Stream
    {
        public long Written { get; private set; }
        public int Writes { get; private set; }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (Written + buffer.Length > failAt)
                throw new IOException("destination failed");

            Written += buffer.Length;
            Writes++;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
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
