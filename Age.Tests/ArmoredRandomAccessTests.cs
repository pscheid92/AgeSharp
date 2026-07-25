using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Random access through ASCII armor. Armor is order-preserving and
/// position-computable — 48 binary bytes per 64 base64 columns, only the final line
/// short — so a binary offset translates to a text position arithmetically. These
/// tests pin that the translation agrees with reading forward, at the boundaries
/// where the arithmetic is easiest to get wrong.
/// </summary>
public class ArmoredRandomAccessTests
{
    private const int BytesPerArmorLine = 48;

    private static byte[] Pattern(int length)
    {
        var data = new byte[length];
        new Random(1234).NextBytes(data);
        return data;
    }

    private static MemoryStream Armored(byte[] plaintext, IRecipient recipient) =>
        new(Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, recipient));

    private static byte[] ReadAt(Stream stream, long offset, int count)
    {
        stream.Position = offset;

        var buffer = new byte[count];
        var total = 0;

        while (total < count)
        {
            var read = stream.Read(buffer.AsSpan(total));
            if (read == 0)
                break;

            total += read;
        }

        return total == count ? buffer : buffer[..total];
    }

    // --- the basic contract --------------------------------------------------

    [Fact]
    public void ArmoredSource_IsSeekable_AndReportsPlaintextLength()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.Length, stream.Length);
    }

    [Fact]
    public void NonSeekableArmoredSource_StaysForwardOnly()
    {
        // Geometry needs a seekable source; a pipe still decrypts, just forward-only.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var inner = Armored(plaintext, identity.Recipient);
        using var source = new NonSeekableStream(inner);
        using var stream = Age.DecryptReader(source, identity);

        Assert.False(stream.CanSeek);

        using var output = new MemoryStream();
        stream.CopyTo(output);
        Assert.Equal(plaintext, output.ToArray());
    }

    // --- offsets agree with a forward read -----------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(BytesPerArmorLine - 1)]   // last byte of the first armor line
    [InlineData(BytesPerArmorLine)]       // first byte of the second
    [InlineData(BytesPerArmorLine + 1)]
    [InlineData(BytesPerArmorLine * 7 + 13)]
    [InlineData(40_000)]
    public void ReadAtOffset_MatchesTheForwardRead(int offset)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        var expected = plaintext.AsSpan(offset, Math.Min(1000, plaintext.Length - offset)).ToArray();
        Assert.Equal(expected, ReadAt(stream, offset, expected.Length));
    }

    [Fact]
    public void EveryArmorLineBoundary_ReadsCorrectly()
    {
        // Walks the whole file one armor line at a time: an off-by-one in the stride
        // or the terminator width would show up within the first few lines.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(BytesPerArmorLine * 200 + 17);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        for (var offset = 0; offset < plaintext.Length; offset += BytesPerArmorLine)
        {
            var count = Math.Min(BytesPerArmorLine, plaintext.Length - offset);
            Assert.Equal(plaintext.AsSpan(offset, count).ToArray(), ReadAt(stream, offset, count));
        }
    }

    [Fact]
    public void SeekingBackwards_Works()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(80_000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        Assert.Equal(plaintext.AsSpan(70_000, 100).ToArray(), ReadAt(stream, 70_000, 100));
        Assert.Equal(plaintext.AsSpan(10, 100).ToArray(), ReadAt(stream, 10, 100));
        Assert.Equal(plaintext.AsSpan(50_000, 100).ToArray(), ReadAt(stream, 50_000, 100));
    }

    [Fact]
    public void SeekFromEnd_LandsOnTheLastBytes()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        stream.Seek(-64, SeekOrigin.End);
        Assert.Equal(plaintext.AsSpan(^64).ToArray(), ReadAt(stream, stream.Position, 64));
    }

    [Fact]
    public void SeekFromCurrent_IsRelative()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        stream.Position = 1000;
        stream.Seek(500, SeekOrigin.Current);

        Assert.Equal(1500, stream.Position);
        Assert.Equal(plaintext.AsSpan(1500, 50).ToArray(), ReadAt(stream, stream.Position, 50));
    }

    [Fact]
    public void ReadingToTheEnd_StopsAtLength()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(5000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        stream.Position = plaintext.Length - 10;
        Assert.Equal(plaintext.AsSpan(^10).ToArray(), ReadAt(stream, stream.Position, 10));

        Assert.Equal(0, stream.Read(new byte[16], 0, 16));
    }

    // --- sizes where the geometry is degenerate ------------------------------

    [Theory]
    [InlineData(0)]                        // empty plaintext
    [InlineData(1)]
    [InlineData(BytesPerArmorLine)]        // exactly one armor line of payload
    [InlineData(BytesPerArmorLine * 3)]    // exact multiple: no short final line
    public void SmallAndExactSizes_ReportTheRightLength(int size)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(size);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        Assert.Equal(size, stream.Length);

        using var output = new MemoryStream();
        stream.CopyTo(output);
        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void MultiChunkPayload_SeeksAcrossChunkBoundaries()
    {
        // Two independent geometries interact here: the 64 KiB STREAM chunk and the
        // 48-byte armor line, which do not divide evenly into one another.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(64 * 1024 * 3 + 999);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        using var stream = Age.DecryptReader(ciphertext, identity);

        foreach (var offset in new[] { 65_535, 65_536, 65_537, 131_071, 131_072, 196_608 })
            Assert.Equal(plaintext.AsSpan(offset, 64).ToArray(), ReadAt(stream, offset, 64));
    }

    // --- armor written by other tools ----------------------------------------

    [Fact]
    public void CrlfArmor_IsSeekable()
    {
        // The terminator width feeds the stride directly, so CRLF is not cosmetic.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(20_000);

        var lf = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
        var crlf = System.Text.Encoding.ASCII.GetBytes(
            System.Text.Encoding.ASCII.GetString(lf).Replace("\n", "\r\n"));

        using var source = new MemoryStream(crlf);
        using var stream = Age.DecryptReader(source, identity);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.Length, stream.Length);
        Assert.Equal(plaintext.AsSpan(15_000, 100).ToArray(), ReadAt(stream, 15_000, 100));
    }

    [Fact]
    public void ArmorWithLeadingBlankLines_IsSeekable()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(20_000);

        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
        var padded = (byte[])[.. "\n\n  \n"u8, .. armored];

        using var source = new MemoryStream(padded);
        using var stream = Age.DecryptReader(source, identity);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.AsSpan(15_000, 100).ToArray(), ReadAt(stream, 15_000, 100));
    }

    [Fact]
    public void ArmorWithTrailingWhitespace_IsSeekable()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(20_000);

        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
        var padded = (byte[])[.. armored, .. "\n\n  \n"u8];

        using var source = new MemoryStream(padded);
        using var stream = Age.DecryptReader(source, identity);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.Length, stream.Length);
    }

    // --- async keeps the same behaviour --------------------------------------

    [Fact]
    public async Task DecryptReaderAsync_ArmoredSource_IsSeekable()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var ciphertext = Armored(plaintext, identity.Recipient);
        await using var stream = await Age.DecryptReaderAsync(ciphertext, [identity]);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.Length, stream.Length);

        stream.Position = 30_000;
        var buffer = new byte[100];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total));
            if (read == 0) break;
            total += read;
        }

        Assert.Equal(plaintext.AsSpan(30_000, 100).ToArray(), buffer);
    }

    [Fact]
    public async Task ArmoredSeek_DoesNoBlockingIo()
    {
        // Stream.Seek is synchronous by contract, so the sub-line remainder cannot be
        // read there — it is deferred to the next read, which may be asynchronous.
        // This is what pins that.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(50_000);

        using var inner = Armored(plaintext, identity.Recipient);
        await using var source = new ThrowOnSyncIoStream(inner);
        await using var stream = await Age.DecryptReaderAsync(source, [identity]);

        stream.Position = 20_001;   // deliberately not on an armor line boundary

        var buffer = new byte[100];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total));
            if (read == 0) break;
            total += read;
        }

        Assert.Equal(plaintext.AsSpan(20_001, 100).ToArray(), buffer);
    }

    // --- malformed geometry falls back rather than lying ---------------------

    [Fact]
    public void ShortLineInTheMiddle_DoesNotDecodeToGarbage()
    {
        // A short middle line breaks the offset arithmetic. The AEAD is what makes
        // that safe: the bytes at the computed position fail authentication rather
        // than decrypting to something plausible.
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(20_000);

        var text = System.Text.Encoding.ASCII.GetString(
            Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient));

        var lines = text.Split('\n').ToList();
        lines[5] = lines[5][..32];   // corrupt the geometry mid-body

        using var source = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(string.Join('\n', lines)));

        Assert.ThrowsAny<AgeException>(() =>
        {
            using var stream = Age.DecryptReader(source, identity);
            using var output = new MemoryStream();
            stream.CopyTo(output);
        });
    }
}
