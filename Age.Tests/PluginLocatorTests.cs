using Age.Plugin;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Resolution cases beyond those in <see cref="PluginProcessTests"/>, which covers the
/// working-directory refusal and the basic found/not-found pair. Together these pin the S1
/// property: only rooted <c>PATH</c> entries are searched, and only an absolute path is ever
/// handed to the process launcher.
/// </summary>
public sealed class PluginLocatorTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-locator-").FullName;

    // Best-effort: on Windows a just-written executable is often still held open by the virus
    // scanner, and a temp directory the OS reclaims anyway must not fail a passing test.
    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left for the OS to reclaim.
        }
    }

    private string Plant(string name, string? directory = null)
    {
        var path = Path.Combine(directory ?? _dir, name);
        File.WriteAllText(path, OperatingSystem.IsWindows() ? "@echo off\r\n" : "#!/bin/sh\nexit 0\n");

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        return path;
    }

    // On Windows a bare name is not executable; the planted file needs a PATHEXT suffix.
    private static string FileNameFor(string stem) => OperatingSystem.IsWindows() ? stem + ".CMD" : stem;

    private const string WindowsPathExt = ".COM;.EXE;.BAT;.CMD";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void MissingPath_ReturnsNull(string? searchPath)
    {
        Assert.Null(PluginLocator.Find("age-plugin-anything", searchPath, null));
    }

    [Fact]
    public void SearchesBeyondTheFirstEntry()
    {
        var second = Directory.CreateDirectory(Path.Combine(_dir, "second")).FullName;
        Plant(FileNameFor("age-plugin-later"), second);

        var result = PluginLocator.Find("age-plugin-later", $"{_dir}{Path.PathSeparator}{second}", WindowsPathExt);

        Assert.NotNull(result);
        Assert.StartsWith(second, result, StringComparison.Ordinal);
    }

    [Fact]
    public void EarlierPathEntryWins()
    {
        var second = Directory.CreateDirectory(Path.Combine(_dir, "second")).FullName;
        Plant(FileNameFor("age-plugin-dup"));
        Plant(FileNameFor("age-plugin-dup"), second);

        var result = PluginLocator.Find("age-plugin-dup", $"{_dir}{Path.PathSeparator}{second}", WindowsPathExt);

        Assert.NotNull(result);
        Assert.DoesNotContain("second", result, StringComparison.Ordinal);
    }

    // A PATH entry the platform cannot express must be skipped, not throw out of Find.
    [Fact]
    public void UnusablePathEntry_IsSkippedRatherThanThrowing()
    {
        Plant(FileNameFor("age-plugin-ok"));

        var result = PluginLocator.Find("age-plugin-ok", $"\0invalid{Path.PathSeparator}{_dir}", WindowsPathExt);

        Assert.NotNull(result);
        Assert.StartsWith(_dir, result, StringComparison.Ordinal);
    }

    // The single-argument overload reads the real environment; assert it does not fall back to
    // the working directory, which is the whole point of the type.
    [Fact]
    public void EnvironmentOverload_DoesNotSearchTheWorkingDirectory()
    {
        var name = "age-plugin-envprobe" + Guid.NewGuid().ToString("N")[..8];
        Plant(FileNameFor(name));

        var previous = Directory.GetCurrentDirectory();

        try
        {
            Directory.SetCurrentDirectory(_dir);
            Assert.Null(PluginLocator.Find(name));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
        }
    }

    [SkippableFact]
    public void PathExtSuffixesAreTried_OnWindows()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "PATHEXT is a Windows concept");

        Plant("age-plugin-ext.CMD");

        Assert.NotNull(PluginLocator.Find("age-plugin-ext", _dir, WindowsPathExt));
        Assert.Null(PluginLocator.Find("age-plugin-ext", _dir, ".EXE"));
    }

    [SkippableFact]
    public void EmptyPathExtFallsBackToTheDefaultList_OnWindows()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "PATHEXT is a Windows concept");

        Plant("age-plugin-default.EXE");

        Assert.NotNull(PluginLocator.Find("age-plugin-default", _dir, null));
        Assert.NotNull(PluginLocator.Find("age-plugin-default", _dir, ""));
    }
}
