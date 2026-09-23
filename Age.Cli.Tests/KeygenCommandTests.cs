using System.Globalization;
using Xunit;

namespace Age.Cli.Tests;

public sealed class KeygenCommandTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-keygen-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    // The timestamp is a machine-readable RFC 3339 line, so it must not follow the user's
    // culture: under th-TH the Buddhist calendar made the year 2569, and cultures with another
    // time separator changed the ':'s.
    [Fact]
    public void CreatedTimestamp_IsTheSameInEveryCulture()
    {
        var path = Path.Combine(_dir, "key.txt");
        var culture = CultureInfo.CurrentCulture;

        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("th-TH");
            using var console = new ConsoleCapture();
            Assert.Equal(0, KeygenCommand.Execute(path, convertToPublic: false, postQuantum: false, inputPath: null));
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
        }

        var created = File.ReadLines(path).First()["# created: ".Length..];
        var parsed = DateTime.ParseExact(created, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

        Assert.InRange(parsed, DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddMinutes(5));
    }
}
