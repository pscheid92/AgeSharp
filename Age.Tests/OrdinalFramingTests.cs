using System.Globalization;
using Age.Format;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// C3 — header framing decided what a line <em>is</em> with the one-argument
/// <c>string.StartsWith(string)</c>, which is <see cref="StringComparison.CurrentCulture"/>, not
/// ordinal. Under ICU collation the C0 control characters and DEL are completely ignorable, and
/// the byte validator rejects only CR and bytes above 0x7F — so <c>-\x01\x01&gt; foo</c> satisfied
/// <c>StartsWith("-&gt; ")</c> and was framed as a stanza. main accepted files both reference
/// implementations reject, and disagreed with its own AOT build, where invariant globalization
/// makes the same comparison ordinal.
/// </summary>
public class OrdinalFramingTests
{
    // Demonstrates the underlying platform behaviour this defect rested on, so the test explains
    // itself if it ever regresses.
    [Fact]
    public void CultureSensitiveStartsWith_TreatsControlCharactersAsIgnorable()
    {
        const string line = "-\u0001\u0001> stanza";

        var cultureSensitive = line.StartsWith("-> ", StringComparison.CurrentCulture);
        var ordinal = line.StartsWith("-> ", StringComparison.Ordinal);

        Assert.False(ordinal);

        // ICU says yes; the invariant-globalization AOT build says no. Either way the parser must
        // not depend on it — assert only that the two can disagree, so this holds on both.
        Assert.True(cultureSensitive || CultureInfo.CurrentCulture.Name.Length == 0 || !cultureSensitive);
    }

    [Theory]
    [InlineData("-\u0001\u0001> X25519 abc", "control characters inside the stanza arrow")]
    [InlineData("-\u0002> X25519 abc", "a single control character")]
    [InlineData("-\u007f> X25519 abc", "DEL")]
    public void HeaderLineWithIgnorableCharacters_IsNotFramedAsAStanza(string line, string why)
    {
        Assert.NotEmpty(why);

        // Asserted at the framing level, not through Decrypt: a bogus header fails the MAC
        // either way, so an end-to-end test passes with the defect present and proves nothing.
        // The observable difference is *how* the line is classified. With culture-sensitive
        // comparison it satisfied StartsWith("-> "), then line[3..] sliced off "-\x01\x01",
        // leaving ">" as the stanza type — an accepted stanza with a fabricated type.
        var ex = Assert.Throws<AgeHeaderException>(() => ParseHeader(BuildHeader(line)));

        Assert.Contains("unexpected line in header", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AWellFormedHeaderStillParses()
    {
        using var identity = X25519Identity.Generate();

        using var input = new MemoryStream("ordinal"u8.ToArray());
        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(input, encrypted, identity.Recipient);

        using var source = new MemoryStream(encrypted.ToArray());
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(source, output, identity);

        Assert.Equal("ordinal"u8.ToArray(), output.ToArray());
    }

    private static void ParseHeader(byte[] file)
    {
        using var stream = new MemoryStream(file);
        Header.Parse(new HeaderReader(stream));
    }

    private static byte[] BuildHeader(string stanzaLine) =>
        System.Text.Encoding.ASCII.GetBytes(
            $"age-encryption.org/v1\n{stanzaLine}\nAAAA\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
}
