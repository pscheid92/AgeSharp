using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// A secret key file is readable by its owner alone from the moment it exists, and is only ever
/// a new file. Writing first and restricting afterwards left a window in which the key sat on
/// disk as 0644; checking for an existing file and then writing left a window in which a symlink
/// planted at the path would be followed. Both windows are races and cannot be reproduced here,
/// so these tests pin the contract that closes them.
/// </summary>
public sealed class SecretKeyFileTests : IDisposable
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-secret-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    // Behind a guard the platform analyzer recognises; it does not read Skip.If as one.
    private static UnixFileMode ModeOf(string path)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Unix file modes");

        return File.GetUnixFileMode(path);
    }

    [SkippableFact]
    public void Create_MakesAFileOnlyTheOwnerCanUse()
    {
        Skip.If(OperatingSystem.IsWindows(), "Unix file modes");

        var path = Path.Combine(_dir, "key.txt");
        SecretKeyFile.Create(path, "AGE-SECRET-KEY-1...\n");

        Assert.Equal(OwnerOnly, ModeOf(path));
    }

    [Fact]
    public void Create_WritesTheContentsVerbatim()
    {
        var path = Path.Combine(_dir, "key.txt");
        SecretKeyFile.Create(path, "# comment\nAGE-SECRET-KEY-1...\n");

        // Byte for byte: in particular no UTF-8 byte order mark ahead of the first line.
        Assert.Equal("# comment\nAGE-SECRET-KEY-1...\n"u8.ToArray(), File.ReadAllBytes(path));
    }

    [Fact]
    public void Create_RefusesAnExistingFile_AndLeavesItAlone()
    {
        var path = Path.Combine(_dir, "key.txt");
        File.WriteAllText(path, "someone else's key");

        Assert.ThrowsAny<IOException>(() => SecretKeyFile.Create(path, "new key"));
        Assert.Equal("someone else's key", File.ReadAllText(path));
    }

    [SkippableFact]
    public void Create_RefusesASymlink_AndWritesNothingThroughIt()
    {
        Skip.If(OperatingSystem.IsWindows(), "creating symlinks needs a privilege on Windows");

        var target = Path.Combine(_dir, "attacker-chosen.txt");
        var path = Path.Combine(_dir, "key.txt");
        File.CreateSymbolicLink(path, target);

        Assert.ThrowsAny<IOException>(() => SecretKeyFile.Create(path, "new key"));
        Assert.False(File.Exists(target));
    }

    [SkippableFact]
    public void Keygen_WithOutput_WritesAnOwnerOnlyKeyFile()
    {
        Skip.If(OperatingSystem.IsWindows(), "Unix file modes");

        var path = Path.Combine(_dir, "key.txt");

        Assert.Equal(0, KeygenCommand.Execute(path, convertToPublic: false, postQuantum: false, inputPath: null));
        Assert.Equal(OwnerOnly, ModeOf(path));

        var secret = File.ReadAllLines(path).Single(line => line.StartsWith("AGE-SECRET-KEY-", StringComparison.Ordinal));
        using var identity = X25519Identity.Parse(secret);
    }

    [Fact]
    public void Keygen_WithExistingOutput_Refuses_AndLeavesItAlone()
    {
        var path = Path.Combine(_dir, "key.txt");
        File.WriteAllText(path, "someone else's key");

        Assert.Equal(1, KeygenCommand.Execute(path, convertToPublic: false, postQuantum: false, inputPath: null));
        Assert.Equal("someone else's key", File.ReadAllText(path));
    }
}
