using System.IO.Compression;
using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Armor decoding fed as bytes: the rules live apart from the stream they arrive on, so reading
/// synchronously or asynchronously, in large reads or one byte at a time, gives the same bytes or
/// the same failure.
/// </summary>
public class ArmorDecodingTests
{
    public static TheoryData<string> ArmoredVectors()
    {
        var data = new TheoryData<string>();

        foreach (var path in Directory.EnumerateFiles(Path.Combine(AppContext.BaseDirectory, "ConformanceVectors")).Order())
        {
            if (!Path.GetFileName(path).Contains('.') && !Body(path).AsSpan().StartsWith("age-encryption.org/v1\n"u8))
                data.Add(Path.GetFileName(path));
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(ArmoredVectors))]
    public async Task DearmoringSyncAsyncOrOneByteAtATime_GivesTheSameResult(string vector)
    {
        var body = Body(Path.Combine(AppContext.BaseDirectory, "ConformanceVectors", vector));

        var sync = Dearmor(new MemoryStream(body));
        var async = await DearmorAsync(new MemoryStream(body));
        var trickled = Dearmor(new OneByteAtATime(body));
        var trickledAsync = await DearmorAsync(new OneByteAtATime(body));

        Assert.Equal(sync, async);
        Assert.Equal(sync, trickled);
        Assert.Equal(sync, trickledAsync);
    }

    // A spec armor line is 64 characters. The bound only has to stop a hostile line that never
    // ends, so it sits at 1 KiB, as decided in the API review.
    [Theory]
    [InlineData(1024, false)]
    [InlineData(1025, true)]
    public void AnArmorLineIsBoundAt1KiB(int lineBytes, bool refused)
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n" + new string('A', lineBytes) + "\n";

        var result = Dearmor(new MemoryStream(Encoding.ASCII.GetBytes(text)));

        Assert.Equal(1024, AgeLimits.MaxArmorLineBytes);
        Assert.Equal(refused, result.Contains("exceeds 1024 bytes"));
    }

    // After the footer, fewer than 1024 bytes of whitespace are allowed, counted byte by byte as
    // they arrived, CRs included, as go-age counts them.
    [Theory]
    [InlineData("\n", 1023, false)]
    [InlineData("\n", 1024, true)]
    [InlineData("\r\n", 511, false)] // 1022 bytes
    [InlineData("\r\n", 512, true)] // 1024 bytes
    public void WhitespaceAfterTheFooter_IsAllowedUpTo1023Bytes(string ending, int count, bool refused)
    {
        var text = Armor("hello armor"u8) + string.Concat(Enumerable.Repeat(ending, count));

        var result = Dearmor(new MemoryStream(Encoding.ASCII.GetBytes(text)));

        Assert.Equal(refused, result.Contains("whitespace after the armor footer"));
    }

    // A byte outside ASCII is named as '?', as it was when a StreamReader decoded the armor.
    [Fact]
    public void ANonAsciiByteInTheBody_IsNamedAsAQuestionMark()
    {
        var armored = Encoding.ASCII.GetBytes(Armor("hello armor"u8));
        var body = Array.IndexOf(armored, (byte)'\n') + 1;
        armored[body] = 0xE9;

        Assert.Contains("invalid character in armor body: '?'", Dearmor(new MemoryStream(armored)));
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\t")]
    public void WhitespaceAtEitherEndOfABodyLine_IsRefused(string whitespace)
    {
        var armored = Armor("hello armor"u8).Split('\n');

        foreach (var changed in new[] { whitespace + armored[1], armored[1] + whitespace })
        {
            var text = string.Join('\n', [armored[0], changed, .. armored[2..]]);
            Assert.Contains("whitespace in armor body line", Dearmor(new MemoryStream(Encoding.ASCII.GetBytes(text))));
        }
    }

    // Reading nothing reads nothing, without touching the input; and the array-based async
    // read is the same read.
    [Fact]
    public async Task EmptyReadsReturnZero_AndTheArrayBasedAsyncReadDecodesToo()
    {
        var armored = Encoding.ASCII.GetBytes(Armor("hello armor"u8));
        using var dearmored = AsciiArmor.Dearmor(new MemoryStream(armored));

        Assert.Equal(0, dearmored.Read(Span<byte>.Empty));
        Assert.Equal(0, await dearmored.ReadAsync(Memory<byte>.Empty));

        var buffer = new byte[64];
        var read = await dearmored.ReadAsync(buffer, 0, buffer.Length, CancellationToken.None);
        Assert.Equal("hello armor"u8.ToArray(), buffer[..read]);
    }

    // A malformed last line is "invalid base64"; a well-formed one whose padding covers bits
    // that are not zero is "non-canonical". These are the old decoder's answers, line by line.
    [Theory]
    [InlineData("ABA=", null)]
    [InlineData("AA==", null)]
    [InlineData("ABC=", "non-canonical base64 in armor")]
    [InlineData("AF==", "non-canonical base64 in armor")]
    [InlineData("ABC", "invalid base64 in armor")]
    [InlineData("ABCDEF=", "invalid base64 in armor")]
    [InlineData("A=BC", "invalid base64 in armor")]
    [InlineData("AB=C", "invalid base64 in armor")]
    [InlineData("A===", "invalid base64 in armor")]
    public void AMalformedLastLine_IsInvalid_AndStrayPaddingBits_AreNonCanonical(string line, string? refusal)
    {
        var text = $"-----BEGIN AGE ENCRYPTED FILE-----\n{line}\n-----END AGE ENCRYPTED FILE-----\n";

        var result = Dearmor(new MemoryStream(Encoding.ASCII.GetBytes(text)));

        if (refusal is null)
            Assert.DoesNotContain("Exception", result);
        else
            Assert.Equal($"AgeArmorException: {refusal}", result);
    }

    private static string Armor(ReadOnlySpan<byte> bytes)
    {
        using var output = new MemoryStream();
        AgeSharp.Armor.Encode(new MemoryStream(bytes.ToArray()), output);
        return Encoding.ASCII.GetString(output.ToArray());
    }

    // Everything a dearmoring leaves: the decoded bytes, or the failure and its message.
    private static string Dearmor(Stream input)
    {
        try
        {
            using var dearmored = AsciiArmor.Dearmor(input);
            using var output = new MemoryStream();
            dearmored.CopyTo(output);
            return Convert.ToHexString(output.ToArray());
        }
        catch (AgeException ex)
        {
            return $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    private static async Task<string> DearmorAsync(Stream input)
    {
        try
        {
            await using var dearmored = await AsciiArmor.DearmorAsync(input, CancellationToken.None);
            using var output = new MemoryStream();
            await dearmored.CopyToAsync(output);
            return Convert.ToHexString(output.ToArray());
        }
        catch (AgeException ex)
        {
            return $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    private static byte[] Body(string path)
    {
        var all = File.ReadAllBytes(path);
        var end = all.AsSpan().IndexOf("\n\n"u8);
        var metadata = Encoding.UTF8.GetString(all, 0, end);
        var body = all[(end + 2)..];

        if (!metadata.Contains("compressed: zlib"))
            return body;

        using var zlib = new ZLibStream(new MemoryStream(body), CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }

    // A stream that hands out one byte per read, as a slow pipe may.
    private sealed class OneByteAtATime(byte[] bytes) : MemoryStream(bytes)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, 1));

        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(buffer.Length, 1)]);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 1)], cancellationToken);
    }
}
