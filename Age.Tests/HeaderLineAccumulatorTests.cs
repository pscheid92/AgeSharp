using System.Text;
using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Direct tests for the sans-I/O <see cref="HeaderLineAccumulator"/>. The point of
/// the fill/parse split is that line framing, validation, and the size limits can
/// be exercised without any stream — sync and async drivers share exactly this
/// logic.
/// </summary>
public class HeaderLineAccumulatorTests
{
    private const int MaxLine = 64 * 1024;
    private const int MaxHeader = 16 * 1024 * 1024;

    private static List<string> FeedAll(HeaderLineAccumulator acc, string text)
    {
        var lines = new List<string>();
        foreach (var b in Encoding.ASCII.GetBytes(text))
            if (acc.Feed(b) is { } line)
                lines.Add(line);
        return lines;
    }

    [Fact]
    public void Feed_YieldsLinesAtEachNewline_AndTracksRawBytes()
    {
        var acc = new HeaderLineAccumulator(MaxLine, MaxHeader);

        var lines = FeedAll(acc, "age-encryption.org/v1\n-> X25519 abc\n");

        Assert.Equal(["age-encryption.org/v1", "-> X25519 abc"], lines);
        // Raw bytes retain everything fed, newlines included (needed for the MAC).
        Assert.Equal("age-encryption.org/v1\n-> X25519 abc\n", Encoding.ASCII.GetString(acc.RawBytes));
    }

    [Fact]
    public void Feed_EmptyLine_YieldsEmptyString()
    {
        var acc = new HeaderLineAccumulator(MaxLine, MaxHeader);
        Assert.Equal([""], FeedAll(acc, "\n"));
    }

    [Fact]
    public void Feed_CarriageReturn_Throws()
    {
        var acc = new HeaderLineAccumulator(MaxLine, MaxHeader);
        acc.Feed((byte)'a');
        Assert.Throws<AgeFormatException>(() => acc.Feed((byte)'\r'));
    }

    [Fact]
    public void Feed_NonAscii_Throws()
    {
        var acc = new HeaderLineAccumulator(MaxLine, MaxHeader);
        Assert.Throws<AgeFormatException>(() => acc.Feed(0x80));
    }

    [Fact]
    public void Feed_LineExceedingMaxLine_Throws()
    {
        var acc = new HeaderLineAccumulator(maxLineBytes: 4, MaxHeader);

        // 4 bytes fit; the 5th non-LF byte on the same line trips the limit.
        for (var i = 0; i < 4; i++)
            Assert.Null(acc.Feed((byte)'x'));
        Assert.Throws<AgeFormatException>(() => acc.Feed((byte)'x'));
    }

    [Fact]
    public void Feed_HeaderExceedingMaxHeader_Throws()
    {
        var acc = new HeaderLineAccumulator(MaxLine, maxHeaderBytes: 3);

        // Newlines count toward the header total, so 3 bytes are accepted then the 4th throws.
        acc.Feed((byte)'a');
        acc.Feed((byte)'\n');
        acc.Feed((byte)'b');
        Assert.Throws<AgeFormatException>(() => acc.Feed((byte)'c'));
    }

    [Fact]
    public void FinishAtEof_CleanBoundary_ReturnsNull()
    {
        var acc = new HeaderLineAccumulator(MaxLine, MaxHeader);
        FeedAll(acc, "line\n");
        Assert.Null(acc.FinishAtEof());
    }

    [Fact]
    public void FinishAtEof_PartialLine_Throws()
    {
        var acc = new HeaderLineAccumulator(MaxLine, MaxHeader);
        acc.Feed((byte)'x'); // no trailing newline
        Assert.Throws<AgeFormatException>(() => acc.FinishAtEof());
    }
}
