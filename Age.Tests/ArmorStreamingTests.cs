using System.Text;
using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// The dearmor path is sans-I/O: line framing and decoding are driven from either a
/// synchronous or an asynchronous fill, so armored input streams on both paths with
/// no buffering and no blocking I/O on the caller's stream.
/// </summary>
public class ArmorStreamingTests
{
    private static byte[] Armored(byte[] plaintext, IRecipient recipient) =>
        Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, recipient);

    private static byte[] Payload(int size, int seed = 3)
    {
        var buffer = new byte[size];
        new Random(seed).NextBytes(buffer);
        return buffer;
    }

    // --- async streaming, the capability this adds ---

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(47)]        // one short line
    [InlineData(48)]        // exactly one full armor line
    [InlineData(49)]
    [InlineData(70_000)]    // spans several source refills and a STREAM chunk boundary
    public async Task DecryptAsync_Armored_RoundTrips(int size)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(size);

        using var input = new MemoryStream(Armored(plaintext, identity.Recipient));
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity]);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task DecryptReaderAsync_Armored_NonSeekable_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(120_000);

        using var input = new NonSeekableStream(new MemoryStream(Armored(plaintext, identity.Recipient)));
        await using var stream = await Age.DecryptReaderAsync(input, [identity]);
        using var output = new MemoryStream();
        await stream.CopyToAsync(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task ArmoredDecryptAsync_DoesNoBlockingIo()
    {
        // The reason the dearmor had to become sans-I/O: ThrowOnSyncIoStream fails the
        // test if anything calls Read/Write/Flush on the caller's stream.
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(200_000);
        var ciphertext = Armored(plaintext, identity.Recipient);

        using var output = new MemoryStream();
        await Age.DecryptAsync(
            new ThrowOnSyncIoStream(new MemoryStream(ciphertext)),
            new ThrowOnSyncIoStream(output),
            [identity]);

        Assert.Equal(plaintext, output.ToArray());
    }

    // Allocation is now constant in input size (~26 KB whether the input is 8 MiB or
    // 32 MiB, measured out-of-band). That is deliberately not asserted here:
    // GC.GetTotalAllocatedBytes is process-wide, and xUnit runs test classes in
    // parallel, so any such assertion measures the whole suite's noise and flakes.

    // --- framing details the byte-fed accumulator now owns ---

    [Fact]
    public async Task CrlfTerminatedArmor_RoundTrips_OnTheAsyncPath()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(5000);

        var crlf = Encoding.ASCII.GetBytes(
            Encoding.ASCII.GetString(Armored(plaintext, identity.Recipient)).Replace("\n", "\r\n"));

        using var input = new MemoryStream(crlf);
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity]);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void ArmorWithoutATrailingNewline_StillRoundTrips()
    {
        // The final line arrives without an LF, so it is only completed by end-of-input.
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(1000);
        var armored = Armored(plaintext, identity.Recipient);

        var trimmed = armored.AsSpan().TrimEnd((byte)'\n').ToArray();

        Assert.Equal(plaintext, Age.Decrypt(trimmed, identity));
    }

    [Fact]
    public void AnOverlongLine_IsRejected_ByTheAccumulatorsBound()
    {
        // This bound used to live in a pass-through stream wrapper; it now belongs to
        // the line accumulator, so it must still trip on a line that never terminates.
        var options = new AgeDecryptOptions { MaxArmorLineBytes = 128 };
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n" + new string('A', 4096);

        using var input = new MemoryStream(Encoding.ASCII.GetBytes(text));
        using var output = new MemoryStream();
        using var identity = X25519Identity.Generate();

        var ex = Assert.Throws<AgeFormatException>(() => Age.Decrypt(input, output, options, identity));
        Assert.Contains("exceeds", ex.Message);
    }

    [Fact]
    public void ALineSplitAcrossSourceReads_IsFramedCorrectly()
    {
        // The source buffer is 4 KiB, so a large armored file necessarily splits lines
        // across refills; framing state has to survive that.
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(200_000);

        using var input = new DripStream(new MemoryStream(Armored(plaintext, identity.Recipient)), 7);
        using var output = new MemoryStream();
        Age.Decrypt(input, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void TrailingDataAfterTheEndMarker_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var armored = Armored(Payload(100), identity.Recipient);
        var withTrailer = (byte[])[.. armored, .. "not whitespace\n"u8];

        using var input = new MemoryStream(withTrailer);
        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeFormatException>(() => Age.Decrypt(input, output, identity));
        Assert.Contains("trailing data", ex.Message);
    }

    [Fact]
    public void TrailingWhitespaceAfterTheEndMarker_IsAllowed()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(100);
        var armored = Armored(plaintext, identity.Recipient);
        var padded = (byte[])[.. armored, .. "\n\n   \n"u8];

        Assert.Equal(plaintext, Age.Decrypt(padded, identity));
    }

    // --- the dearmor stream's own Stream contract ---

    [Fact]
    public async Task DearmorStream_ByteArrayReadAsync_Works()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(4000);

        using var source = new MemoryStream(Armored(plaintext, identity.Recipient));
        await using var dearmored = AsciiArmor.Dearmor(source, new AgeDecryptOptions().MaxArmorLineBytes);

        using var collected = new MemoryStream();
        var buffer = new byte[512];
        int read;
        while ((read = await dearmored.ReadAsync(buffer, 0, buffer.Length)) > 0)
            collected.Write(buffer, 0, read);

        // Decoding the armor yields the binary age file, which must still decrypt.
        Assert.Equal(plaintext, Age.Decrypt(collected.ToArray(), identity));
    }

    [Fact]
    public void DearmorStream_ZeroLengthRead_ReturnsZero_WithoutConsuming()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Payload(100);

        using var source = new MemoryStream(Armored(plaintext, identity.Recipient));
        using var dearmored = AsciiArmor.Dearmor(source, new AgeDecryptOptions().MaxArmorLineBytes);

        Assert.Equal(0, dearmored.Read([], 0, 0));

        // The stream must be undisturbed by the empty read.
        using var collected = new MemoryStream();
        dearmored.CopyTo(collected);
        Assert.Equal(plaintext, Age.Decrypt(collected.ToArray(), identity));
    }

    [Fact]
    public void DearmorStream_IsForwardOnlyAndReadOnly()
    {
        using var source = new MemoryStream("-----BEGIN AGE ENCRYPTED FILE-----\n"u8.ToArray());
        using var dearmored = AsciiArmor.Dearmor(source, new AgeDecryptOptions().MaxArmorLineBytes);

        Assert.True(dearmored.CanRead);
        Assert.False(dearmored.CanSeek);
        Assert.False(dearmored.CanWrite);
        dearmored.Flush();

        Assert.Throws<NotSupportedException>(() => dearmored.Length);
        Assert.Throws<NotSupportedException>(() => dearmored.Position);
        Assert.Throws<NotSupportedException>(() => dearmored.Position = 0);
        Assert.Throws<NotSupportedException>(() => dearmored.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => dearmored.SetLength(1));
        Assert.Throws<NotSupportedException>(() => dearmored.Write(new byte[1], 0, 1));
    }

    [Theory]
    [InlineData("AB+=")]   // '+' as the final data character before padding
    [InlineData("A/==")]   // '/' as the final data character before padding
    public void NonCanonicalPadding_OnEveryAlphabetCharacter_IsRejected(string finalLine)
    {
        // Decodes as base64, but the bits the padding claims are unused are not zero.
        var text = $"-----BEGIN AGE ENCRYPTED FILE-----\n{finalLine}\n-----END AGE ENCRYPTED FILE-----\n";
        using var source = new MemoryStream(Encoding.ASCII.GetBytes(text));
        using var dearmored = AsciiArmor.Dearmor(source, new AgeDecryptOptions().MaxArmorLineBytes);

        var ex = Assert.Throws<AgeFormatException>(() => dearmored.CopyTo(Stream.Null));
        Assert.Contains("non-canonical", ex.Message);
    }

    /// <summary>A stream that returns at most <paramref name="chunk"/> bytes per read.</summary>
    private sealed class DripStream(Stream inner, int chunk) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
            => inner.Read(buffer, offset, Math.Min(count, chunk));

        public override int Read(Span<byte> buffer)
            => inner.Read(buffer[..Math.Min(buffer.Length, chunk)]);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
