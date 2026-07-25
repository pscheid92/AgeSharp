using System.Text;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Push-encryption tests for <see cref="Age.EncryptWriter(System.IO.Stream, [System.ReadOnlySpan{IRecipient}])" />
///     and its armored variant. Covers the Phase-4 edge-case matrix — dispose-without-write,
///     plaintext at exact 64 KiB multiples, double dispose, write-after-dispose — plus the
///     stream-ownership contract and an interop cross-check against the reference age CLI.
/// </summary>
public class PushBasedTests
{
    private static byte[] MakePlaintext(int size)
    {
        var data = new byte[size];
        for (var i = 0; i < size; i++)
            data[i] = (byte)((i * 31 + 7) & 0xFF);
        return data;
    }

    private static byte[] EncryptWithEncryptWriter(byte[] plaintext, bool armored, params IRecipient[] recipients)
    {
        using var destination = new MemoryStream();
        using (var stream = Age.EncryptWriter(destination, recipients, new AgeEncryptOptions { Armor = armored }))
        {
            stream.Write(plaintext, 0, plaintext.Length);
        }

        return destination.ToArray();
    }

    private static byte[] DecryptWithCSharp(byte[] ciphertext, params IIdentity[] identities)
    {
        using var input = new MemoryStream(ciphertext);
        using var output = new MemoryStream();
        Age.Decrypt(input, output, identities);
        return output.ToArray();
    }

    // --- Round-trip: size × armor matrix, straddling the 64 KiB chunk boundary ---

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(63, false)]
    [InlineData(65535, false)]
    [InlineData(65536, false)]
    [InlineData(65537, false)]
    [InlineData(131072, false)]
    [InlineData(131073, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(63, true)]
    [InlineData(65535, true)]
    [InlineData(65536, true)]
    [InlineData(65537, true)]
    [InlineData(131072, true)]
    [InlineData(131073, true)]
    public void EncryptWriter_Decrypt_RoundTrip(int size, bool armored)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = EncryptWithEncryptWriter(plaintext, armored, identity.Recipient);

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, identity));
    }

    // An empty final chunk is legal only for empty plaintext; a bug that appended one
    // after an exact N×64 KiB plaintext would be rejected on decrypt. Exercised directly.
    [Theory]
    [InlineData(65536)]
    [InlineData(131072)]
    [InlineData(196608)]
    public void EncryptWriter_ExactChunkMultiple_RoundTrip(int size)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[size];
        new Random(42).NextBytes(plaintext);

        var ciphertext = EncryptWithEncryptWriter(plaintext, false, identity.Recipient);

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, identity));
    }

    // --- Dispose-without-write emits a valid empty-plaintext file ---

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptWriter_DisposeWithoutWrite_ProducesEmptyFile(bool armored)
    {
        using var identity = X25519Identity.Generate();

        using var destination = new MemoryStream();
        using (Age.EncryptWriter(destination, [identity.Recipient], new AgeEncryptOptions { Armor = armored }))
        {
            // No write: the header, payload nonce, and a final empty chunk are still emitted.
        }

        var ciphertext = destination.ToArray();
        Assert.NotEmpty(ciphertext);
        Assert.Empty(DecryptWithCSharp(ciphertext, identity));
    }

    // --- Fragmented writes stress the chunk-buffering / boundary logic ---

    [Fact]
    public void EncryptWriter_ByteByByteWrites_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[130_000]; // spans three chunks
        new Random(42).NextBytes(plaintext);

        using var destination = new MemoryStream();
        using (var stream = Age.EncryptWriter(destination, [identity.Recipient]))
        {
            foreach (var b in plaintext)
                stream.WriteByte(b);
        }

        Assert.Equal(plaintext, DecryptWithCSharp(destination.ToArray(), identity));
    }

    // --- Double dispose is a no-op; write-after-dispose throws ---

    [Fact]
    public void EncryptWriter_DoubleDispose_IsNoOp()
    {
        using var identity = X25519Identity.Generate();

        using var destination = new MemoryStream();
        var stream = Age.EncryptWriter(destination, [identity.Recipient]);
        stream.Write("hello"u8);
        stream.Dispose();
        var afterFirst = destination.ToArray();

        stream.Dispose(); // second dispose must neither throw nor emit more bytes

        Assert.Equal(afterFirst, destination.ToArray());
        Assert.Equal("hello"u8.ToArray(), DecryptWithCSharp(afterFirst, identity));
    }

    [Fact]
    public void EncryptWriter_WriteAfterDispose_Throws()
    {
        using var identity = X25519Identity.Generate();

        using var destination = new MemoryStream();
        var stream = Age.EncryptWriter(destination, [identity.Recipient]);
        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => stream.Write("x"u8.ToArray(), 0, 1));
        Assert.Throws<ObjectDisposedException>(() => stream.WriteByte(0));
        Assert.Throws<ObjectDisposedException>(() => stream.Flush());
    }

    // --- Stream contract: capabilities, harmless flush, unsupported members ---

    [Fact]
    public void EncryptWriter_Flush_PropagatesWithoutFinalizing()
    {
        using var identity = X25519Identity.Generate();

        using var destination = new MemoryStream();
        using var stream = Age.EncryptWriter(destination, [identity.Recipient]);

        stream.Write("flush"u8);
        stream.Flush(); // must not finalize — the stream stays writable
        stream.Write(" more"u8);
    }

    [Fact]
    public void EncryptWriter_UnsupportedMembers_Throw()
    {
        using var identity = X25519Identity.Generate();
        using var destination = new MemoryStream();
        using var stream = Age.EncryptWriter(destination, [identity.Recipient]);

        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => _ = stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => _ = stream.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => _ = stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
    }

    [Fact]
    public void ArmorWriterStream_Capabilities_And_UnsupportedMembers()
    {
        using var destination = new MemoryStream();
        using var armor = new ArmorWriterStream(destination);

        Assert.True(armor.CanWrite);
        Assert.False(armor.CanRead);
        Assert.False(armor.CanSeek);

        armor.Flush(); // propagates to the destination

        Assert.Throws<NotSupportedException>(() => _ = armor.Length);
        Assert.Throws<NotSupportedException>(() => _ = armor.Position);
        Assert.Throws<NotSupportedException>(() => armor.Position = 0);
        Assert.Throws<NotSupportedException>(() => _ = armor.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => _ = armor.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => armor.SetLength(0));
    }

    [Fact]
    public void ArmorWriterStream_DisposeWithoutWrite_EmitsEmptyArmor()
    {
        using var destination = new MemoryStream();
        using (new ArmorWriterStream(destination))
        {
            // Never written to: the begin marker is emitted on dispose alongside the footer.
        }

        var text = Encoding.ASCII.GetString(destination.ToArray());
        Assert.Equal("-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n", text);
    }

    [Fact]
    public void ArmorWriterStream_WriteAfterDispose_Throws()
    {
        var destination = new MemoryStream();
        var armor = new ArmorWriterStream(destination);
        armor.Dispose();

        Assert.Throws<ObjectDisposedException>(() => armor.Write("x"u8.ToArray(), 0, 1));
    }

    // --- Stream ownership: the caller's destination is never disposed ---

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptWriter_DoesNotDisposeDestination(bool armored)
    {
        using var identity = X25519Identity.Generate();

        var destination = new DisposeTrackingStream();
        using (var stream =
               Age.EncryptWriter(destination, [identity.Recipient], new AgeEncryptOptions { Armor = armored }))
        {
            stream.Write("do not dispose me"u8);
        }

        Assert.Equal(0, destination.DisposeCount);
        Assert.Equal("do not dispose me"u8.ToArray(), DecryptWithCSharp(destination.ToArray(), identity));
    }

    // --- Capabilities, argument validation, multi-recipient ---

    [Fact]
    public void EncryptWriter_StreamCapabilities()
    {
        using var identity = X25519Identity.Generate();
        using var destination = new MemoryStream();
        using var stream = Age.EncryptWriter(destination, [identity.Recipient]);

        Assert.True(stream.CanWrite);
        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void EncryptWriter_NoRecipients_Throws()
    {
        using var destination = new MemoryStream();
        Assert.Throws<ArgumentException>(() => Age.EncryptWriter(destination, Array.Empty<IRecipient>()));
    }

    [Fact]
    public void EncryptWriter_MixedPqAndClassicRecipients_Rejected()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        using var destination = new MemoryStream();

        // The label/scrypt checks run eagerly, so the mismatch surfaces from EncryptWriter
        // itself — before any plaintext is written.
        Assert.Throws<AgeException>(() => Age.EncryptWriter(destination, [x25519.Recipient, pq.Recipient]));
    }

    [Fact]
    public void EncryptWriter_DefersHeaderUntilFirstWrite()
    {
        using var identity = X25519Identity.Generate();
        using var destination = new MemoryStream();

        using var stream = Age.EncryptWriter(destination, [identity.Recipient]);

        // Recipient wrapping happened eagerly, but nothing is written to the
        // destination until the first Write (or Dispose).
        Assert.Equal(0, destination.Length);

        stream.Write("now the header lands"u8);
        Assert.True(destination.Length > 0);
    }

    [Fact]
    public void EncryptWriter_Passphrase_RoundTrip()
    {
        var passphrase = new Passphrase("correct horse battery staple", 10);
        var plaintext = MakePlaintext(2048);

        var ciphertext = EncryptWithEncryptWriter(plaintext, false, passphrase);

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, passphrase));
    }

    [Fact]
    public void EncryptWriter_MultipleRecipients_EachIdentityDecrypts()
    {
        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        var plaintext = MakePlaintext(4096);

        var ciphertext = EncryptWithEncryptWriter(plaintext, false, a.Recipient, b.Recipient);

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, a));
        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, b));
    }

    // --- Push-side armor writer matches the established push armor byte-for-byte ---

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(47)]
    [InlineData(48)]
    [InlineData(49)]
    [InlineData(95)]
    [InlineData(96)]
    [InlineData(97)]
    [InlineData(144)]
    [InlineData(200_000)]
    public void ArmorWriterStream_MatchesPushArmor_ByteForByte(int length)
    {
        var data = new byte[length];
        new Random(7).NextBytes(data);

        using var reference = new MemoryStream();
        AsciiArmor.Armor(new MemoryStream(data), reference);

        using var actual = new MemoryStream();
        using (var armor = new ArmorWriterStream(actual))
        {
            armor.Write(data, 0, data.Length);
        }

        Assert.Equal(reference.ToArray(), actual.ToArray());
    }

    // --- Interop: age-sharp push encryption → reference age CLI decrypts ---

    [SkippableTheory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65535, false)]
    [InlineData(65536, false)]
    [InlineData(65537, false)]
    [InlineData(131072, false)]
    [InlineData(1048576, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65535, true)]
    [InlineData(65536, true)]
    [InlineData(65537, true)]
    [InlineData(131072, true)]
    [InlineData(1048576, true)]
    public void EncryptWriter_DecryptWithAge(int size, bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = EncryptWithEncryptWriter(plaintext, armored, identity.Recipient);
        var result = AgeCli.Decrypt(identity.ToSecretString(), ciphertext);

        Assert.Equal(plaintext, result);
    }

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptWriter_DisposeWithoutWrite_DecryptsEmptyWithAge(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();

        using var destination = new MemoryStream();
        using (Age.EncryptWriter(destination, [identity.Recipient], new AgeEncryptOptions { Armor = armored }))
        {
        }

        Assert.Empty(AgeCli.Decrypt(identity.ToSecretString(), destination.ToArray()));
    }

    /// <summary>
    ///     A write-only stream that records how many times it was disposed while keeping its
    ///     buffered bytes readable, so tests can assert the push writer left the caller's
    ///     destination open.
    /// </summary>
    private sealed class DisposeTrackingStream : Stream
    {
        private readonly MemoryStream _inner = new();

        public int DisposeCount { get; private set; }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public byte[] ToArray()
        {
            return _inner.ToArray();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            _inner.Write(buffer);
        }

        public override void Flush()
        {
            _inner.Flush();
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

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                DisposeCount++;

            // Deliberately does not dispose _inner: tests read the bytes afterward.
            base.Dispose(disposing);
        }
    }
}