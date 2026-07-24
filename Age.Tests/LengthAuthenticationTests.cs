using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// The plaintext length reported by a seekable decrypt stream is authenticated
/// before it is exposed: opening decrypts the final chunk <em>as a final chunk</em>,
/// which is the only way to tell a truncated file from a genuinely shorter one.
/// </summary>
/// <remarks>
/// Chunk arithmetic alone cannot do it — a truncation landing on a chunk boundary
/// leaves a structurally valid payload. Before this, such a file reported a
/// plausible wrong <c>Length</c> with no error, while the forward-only path threw on
/// reaching the missing tail. Both reference implementations authenticate here too.
/// </remarks>
public class LengthAuthenticationTests
{
    private static byte[] Ciphertext(int size, IRecipient recipient, out byte[] plaintext)
    {
        plaintext = new byte[size];
        new Random(42).NextBytes(plaintext);
        return Age.Encrypt(plaintext, recipient);
    }

    [Fact]
    public void TruncatedPayload_ThrowsAtOpen_RatherThanReportingAWrongLength()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(200_000, identity.Recipient, out _);

        // Drop a whole chunk: the remainder still forms a valid-looking layout.
        var truncated = ciphertext[..(ciphertext.Length - 40_000)];

        Assert.Throws<AgeAuthenticationException>(() =>
            Age.OpenRead(new MemoryStream(truncated), identity));
    }

    [Fact]
    public async Task TruncatedPayload_ThrowsAtOpen_OnTheAsyncPathToo()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(200_000, identity.Recipient, out _);
        var truncated = ciphertext[..(ciphertext.Length - 40_000)];

        await Assert.ThrowsAsync<AgeAuthenticationException>(async () =>
            await Age.OpenReadAsync(new MemoryStream(truncated), [identity]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(65535)]
    [InlineData(65536)]          // exactly one chunk
    [InlineData(65537)]
    [InlineData(65536 * 2)]      // exact multiple of the chunk size
    public void IntactPayload_ReportsTheAuthenticatedLength(int size)
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(size, identity.Recipient, out var plaintext);

        using var stream = Age.OpenRead(new MemoryStream(ciphertext), identity);

        Assert.Equal(plaintext.Length, stream.Length);
    }

    [Fact]
    public void EmptyPlaintext_StillOpensAndReportsZero()
    {
        // The single chunk is empty, which is legal only because it is also the first.
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt(ReadOnlySpan<byte>.Empty, identity.Recipient);

        using var stream = Age.OpenRead(new MemoryStream(ciphertext), identity);

        Assert.Equal(0, stream.Length);
        Assert.Equal(0, stream.Read(new byte[8], 0, 8));
    }

    [Fact]
    public void AuthenticatingTheLength_DoesNotDisturbSubsequentReads()
    {
        // Opening leaves the final chunk in the cache; reading from the start must
        // still produce the whole plaintext in order.
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(150_000, identity.Recipient, out var plaintext);

        using var stream = Age.OpenRead(new MemoryStream(ciphertext), identity);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void SeekToEnd_UsesTheChunkAlreadyAuthenticatedAtOpen()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(150_000, identity.Recipient, out var plaintext);

        using var stream = Age.OpenRead(new MemoryStream(ciphertext), identity);

        stream.Seek(-64, SeekOrigin.End);
        var tail = new byte[64];
        stream.ReadExactly(tail);

        Assert.Equal(plaintext.AsSpan(plaintext.Length - 64).ToArray(), tail);
    }

    [Fact]
    public async Task SourceThatUnderDeliversVsLength_ThrowsAtAsyncOpen()
    {
        // Authenticating the length reads the final chunk, so a source whose Length
        // overstates what it can deliver is caught while opening — on the async path
        // through the same guard the sync one uses.
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(1000, identity.Recipient, out _);

        using var lying = new InflatedLengthStream(new MemoryStream(ciphertext), extra: 64);

        await Assert.ThrowsAsync<AgeAuthenticationException>(async () =>
            await Age.OpenReadAsync(lying, [identity]));
    }

    /// <summary>A seekable stream that reports more bytes than it will ever return.</summary>
    private sealed class InflatedLengthStream(Stream inner, long extra) : Stream
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

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => inner.Read(buffer);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
            => inner.ReadAsync(buffer, cancellationToken);

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task AsyncSeekablePath_DoesNoBlockingIo()
    {
        // Authenticating the length reads the final chunk, so the async path needed an
        // asynchronous construction route — otherwise wiring the seekable dispatch
        // into OpenReadAsync would have introduced blocking I/O on the caller's stream.
        using var identity = X25519Identity.Generate();
        var ciphertext = Ciphertext(200_000, identity.Recipient, out var plaintext);

        await using var stream = await Age.OpenReadAsync(
            new ThrowOnSyncIoStream(new MemoryStream(ciphertext)), [identity]);

        Assert.True(stream.CanSeek);

        using var output = new MemoryStream();
        await stream.CopyToAsync(output);
        Assert.Equal(plaintext, output.ToArray());
    }
}
