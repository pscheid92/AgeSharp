using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// <c>age inspect</c>'s size breakdown. The header offset is a position in the binary encoding,
/// so an armored file must be measured by its dearmored length: subtracting the offset from the
/// armored length reported 406,380 bytes of payload for a 300,000-byte file.
/// </summary>
public class InspectCommandTests
{
    [Theory]
    [InlineData(false, 300_000)]
    [InlineData(true, 300_000)]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(true, 2 * 64 * 1024)]
    public void Sizes_AddUpToTheFile_WithThePlaintextAsPayload(bool armor, int plaintextLength)
    {
        using var identity = X25519Identity.Generate();
        var file = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(new byte[plaintextLength]), file, armor, identity.Recipient);
        file.Position = 0;

        var (header, sizes) = InspectCommand.Measure(file);

        Assert.Equal(armor, header.IsArmored);
        Assert.Equal(plaintextLength, sizes.Payload);
        Assert.Equal(file.Length, sizes.Total);
        Assert.Equal(sizes.Total, sizes.Header + sizes.Armor + sizes.Overhead + sizes.Payload);
        Assert.Equal(armor, sizes.Armor > 0);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Execute_PrintsTheBreakdown(bool json)
    {
        using var identity = X25519Identity.Generate();
        var path = Path.GetTempFileName();

        try
        {
            using (var file = File.Create(path))
                AgeEncrypt.Encrypt(new MemoryStream(new byte[300_000]), file, armor: true, identity.Recipient);

            using var console = new ConsoleCapture();
            Assert.Equal(0, InspectCommand.Execute(path, json));

            if (json)
            {
                Assert.Contains("\"armored\": true", console.Out);
                Assert.Contains("\"payload\": 300000", console.Out);
                Assert.Contains("\"armor\": ", console.Out);
            }
            else
            {
                Assert.Contains("This file is ASCII-armored.", console.Out);
                Assert.Contains("Armor overhead", console.Out);
                Assert.Matches(@"Payload\s+300000 bytes", console.Out);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }
}
