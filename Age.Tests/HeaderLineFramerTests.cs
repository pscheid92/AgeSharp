using System.IO.Compression;
using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The header's line framing, fed one byte at a time and never touching a stream: what splits
/// header bytes into lines, refuses what age forbids in them, bounds the header, and keeps the
/// bytes the MAC covers. Reading synchronously or asynchronously only changes where the bytes
/// come from.
/// </summary>
public class HeaderLineFramerTests
{
    [Fact]
    public void ALineEndsAtLf_AndAllBytesAreKept()
    {
        var framer = new HeaderLineFramer();
        var lines = Feed(framer, "age-encryption.org/v1\n-> X25519 abc\n"u8);

        Assert.Equal(["age-encryption.org/v1", "-> X25519 abc"], lines);
        Assert.Equal("age-encryption.org/v1\n-> X25519 abc\n"u8.ToArray(), framer.RawBytes.ToArray());
    }

    [Fact]
    public void ACrIsRefused()
    {
        Assert.Throws<AgeHeaderException>(() => Feed(new HeaderLineFramer(), "line\r\n"u8));
    }

    [Fact]
    public void ANonAsciiByteIsRefused()
    {
        Assert.Throws<AgeHeaderException>(() => Feed(new HeaderLineFramer(), [0x80, 0x0A]));
    }

    [Fact]
    public void TheHeaderIsBounded_LinesAreNotBoundedSeparately()
    {
        // As in go-age, one line may use whatever the header allows.
        var framer = new HeaderLineFramer();
        var line = Feed(framer, [.. Enumerable.Repeat((byte)'a', AgeLimits.MaxHeaderBytes - 1), (byte)'\n']);
        Assert.Single(line);

        var ex = Assert.Throws<AgeHeaderException>(() => framer.Feed((byte)'a'));
        Assert.Contains($"{AgeLimits.MaxHeaderBytes}", ex.Message);
    }

    [Fact]
    public void AtTheEnd_ALineWithoutItsLfIsRefused_AndACleanEndIsNot()
    {
        var clean = new HeaderLineFramer();
        Feed(clean, "done\n"u8);
        Assert.Null(clean.FinishAtEnd());

        var cut = new HeaderLineFramer();
        Feed(cut, "cut"u8);
        Assert.Throws<AgeHeaderException>(() => cut.FinishAtEnd());
    }

    // The prefill must not drop a cut-off last line silently: the parse would then report a
    // missing MAC line, not the reason the header ended.
    [Fact]
    public async Task APrefillThatEndsInsideALine_SaysSo()
    {
        var reader = new HeaderReader(new MemoryStream("age-encryption.org/v1\n-> X25519 ab"u8.ToArray()));

        var ex = await Assert.ThrowsAsync<AgeHeaderException>(() => reader.PrefillAsync(CancellationToken.None).AsTask());

        Assert.Contains("no trailing newline", ex.Message);
    }

    // A header that ends at a line boundary, before its MAC line: the prefill stops at the end,
    // and the parse runs out of lines, as a sync read does.
    [Fact]
    public async Task APrefillThatEndsBeforeTheMacLine_LeavesTheParseToRefuseIt()
    {
        var bytes = "age-encryption.org/v1\n-> X25519 ab\nAAAA\n"u8.ToArray();
        var reader = new HeaderReader(new MemoryStream(bytes));

        await reader.PrefillAsync(CancellationToken.None);

        var ex = Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
        Assert.Contains("unexpected end of header", ex.Message);
        Assert.Equal(bytes, reader.RawBytes.ToArray());
    }

    // --- Sync and async reads agree ------------------------------------------------------------

    public static TheoryData<string> BinaryVectors()
    {
        var data = new TheoryData<string>();

        foreach (var path in Directory.EnumerateFiles(Path.Combine(AppContext.BaseDirectory, "ConformanceVectors")).Order())
        {
            if (!Path.GetFileName(path).Contains('.') && Body(path).AsSpan().StartsWith("age-encryption.org/v1\n"u8))
                data.Add(Path.GetFileName(path));
        }

        return data;
    }

    // Prefilling reads up to the MAC line asynchronously; the same parse then runs over those
    // lines. On every vector the two must agree: the same stanzas, MAC, header length and
    // payload nonce, or a failure of the same kind (an async read may notice a malformed line
    // later than the sync one does, so only the kind is compared).
    [Theory]
    [MemberData(nameof(BinaryVectors))]
    public async Task ReadingAHeaderSyncOrAsync_GivesTheSameResult(string vector)
    {
        var body = Body(Path.Combine(AppContext.BaseDirectory, "ConformanceVectors", vector));

        var sync = Read(body);
        var async = await ReadAsync(body);

        Assert.Equal(sync.Failure, async.Failure);
        Assert.Equal(sync.Header, async.Header);
    }

    private static (string? Failure, string? Header) Read(byte[] body)
    {
        var reader = new HeaderReader(new MemoryStream(body));

        try
        {
            return (null, Describe(Header.Parse(reader), reader));
        }
        catch (Exception ex) when (ex is AgeException or FormatException)
        {
            // Decryption reports a FormatException from the parse as a header failure.
            return (ex is FormatException ? nameof(AgeHeaderException) : ex.GetType().Name, null);
        }
    }

    private static async Task<(string? Failure, string? Header)> ReadAsync(byte[] body)
    {
        var reader = new HeaderReader(new MemoryStream(body));

        try
        {
            await reader.PrefillAsync(CancellationToken.None);
            return (null, Describe(Header.Parse(reader), reader));
        }
        catch (Exception ex) when (ex is AgeException or FormatException)
        {
            // Decryption reports a FormatException from the parse as a header failure.
            return (ex is FormatException ? nameof(AgeHeaderException) : ex.GetType().Name, null);
        }
    }

    // Everything a header read leaves behind that later steps depend on.
    private static string Describe(Header header, HeaderReader reader)
    {
        var nonce = new byte[16];
        var nonceRead = reader.ReadPayloadBytes(nonce);
        var stanzas = header.Stanzas.Select(s => $"{s.Type} {string.Join(' ', s.Args)} {Convert.ToHexString(s.Body.Span)}");

        return $"{string.Join(" | ", stanzas)} mac={Convert.ToHexString(header.Mac)} " +
               $"header={reader.RawBytes.Length} nonce={Convert.ToHexString(nonce.AsSpan(0, nonceRead))}";
    }

    // A vector is key: value lines, a blank line, then the age file, possibly zlib-compressed.
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

    private static List<string> Feed(HeaderLineFramer framer, ReadOnlySpan<byte> bytes)
    {
        var lines = new List<string>();

        foreach (var b in bytes)
        {
            if (framer.Feed(b) is { } line)
                lines.Add(line);
        }

        return lines;
    }
}
