using System.Text;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The header limits go-age enforces since v1.3.2 (internal/format, commit 27188e7): at most
/// 2 MiB of header, 1024 recipient stanzas and 128 arguments per stanza, with no separate limit
/// on a single line. A file go-age rejects must not be accepted here, and the reverse.
/// </summary>
public class HeaderLimitsTests
{
    private const string Intro = "age-encryption.org/v1\n";
    private static readonly string MacLine = "--- " + new string('A', 43) + "\n";

    [Fact]
    public void RecipientStanzas_UpToTheLimit_AreAccepted() =>
        Assert.Equal(1024, Parse(Stanzas(1024)).RecipientCount);

    [Fact]
    public void RecipientStanzas_BeyondTheLimit_AreRejected()
    {
        var ex = Assert.Throws<AgeHeaderException>(() => Parse(Stanzas(1025)));
        Assert.Contains("1024", ex.Message);
    }

    [Fact]
    public void StanzaArguments_UpToTheLimit_AreAccepted() =>
        Assert.Equal(128, Parse(Stanza(arguments: 128)).Recipients[0].Args.Count);

    [Fact]
    public void StanzaArguments_BeyondTheLimit_AreRejected() =>
        Assert.Throws<AgeHeaderException>(() => Parse(Stanza(arguments: 129)));

    // A single line may be as long as the header allows: go-age has no separate line limit.
    [Fact]
    public void LongStanzaLine_IsAccepted() =>
        Assert.Equal(100 * 1024, Parse(StanzaWithArgumentOf(100 * 1024)).Recipients[0].Args[0].Length);

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public void HeaderSize_UpTo2MiB_IsAccepted(int bytesOver, bool accepted)
    {
        // One stanza "-> t <arg>\n\n" between the intro and the MAC line, sized so the header
        // lands exactly on the limit plus bytesOver.
        var fixedBytes = Intro.Length + "-> t ".Length + "\n\n".Length + MacLine.Length;
        var header = StanzaWithArgumentOf(2 * 1024 * 1024 - fixedBytes + bytesOver);

        if (accepted)
            Assert.Equal(2 * 1024 * 1024, Parse(header).PayloadOffset);
        else
            Assert.Throws<AgeHeaderException>(() => Parse(header));
    }

    private static AgeHeader Parse(string header) =>
        AgeHeader.Parse(new MemoryStream(Encoding.ASCII.GetBytes(header)));

    private static string Stanzas(int count) =>
        Intro + string.Concat(Enumerable.Repeat("-> t a\n\n", count)) + MacLine;

    private static string Stanza(int arguments) =>
        Intro + "-> t" + string.Concat(Enumerable.Repeat(" a", arguments)) + "\n\n" + MacLine;

    private static string StanzaWithArgumentOf(int length) =>
        Intro + "-> t " + new string('a', length) + "\n\n" + MacLine;
}
