using Age.Plugin;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Tests that launch (or refuse to launch) a real plugin process. Everything here
/// touches the filesystem and, for the working-directory case, process-global state.
/// </summary>
public class PluginProcessTests
{
    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "agesharp-plugin-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>Writes an executable shell script that records the fact that it ran.</summary>
    private static string PlantScript(string directory, string fileName, string body)
    {
        var path = Path.Combine(directory, fileName);
        File.WriteAllText(path, "#!/bin/sh\n" + body);

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        return path;
    }

    // --- S1: plugin binaries must never be resolved from the current working directory ---

    [SkippableFact]
    public void PluginConnection_NeverExecutesBinaryFromCurrentDirectory()
    {
        Skip.If(OperatingSystem.IsWindows(), "planting an executable requires POSIX file modes");

        var dir = NewTempDir();
        var marker = Path.Combine(dir, "EXECUTED");

        // The plugin name has to be one nothing else could plausibly provide, so a hit
        // can only have come from the current directory.
        var name = "cwdprobe" + Guid.NewGuid().ToString("N")[..8];
        PlantScript(dir, $"age-plugin-{name}", $"touch '{marker}'\nexit 0\n");

        var previous = Directory.GetCurrentDirectory();

        try
        {
            Directory.SetCurrentDirectory(dir);
            var ex = Assert.Throws<AgePluginException>(() => new PluginConnection(name, "recipient-v1"));
            Assert.Contains("plugin not found", ex.Message);
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
        }

        Assert.False(File.Exists(marker), "the planted binary in the current directory was executed");

        Directory.Delete(dir, recursive: true);
    }

    [SkippableFact]
    public void PluginLocator_SkipsRelativeAndEmptyPathEntries()
    {
        Skip.If(OperatingSystem.IsWindows(), "planting an executable requires POSIX file modes");

        var dir = NewTempDir();
        var previous = Directory.GetCurrentDirectory();

        try
        {
            PlantScript(dir, "age-plugin-relprobe", "exit 0\n");
            Directory.SetCurrentDirectory(dir);

            // "" and "." are the two ways a PATH entry names the current directory.
            Assert.Null(PluginLocator.Find("age-plugin-relprobe", "", null));
            Assert.Null(PluginLocator.Find("age-plugin-relprobe", ".", null));
            Assert.Null(PluginLocator.Find("age-plugin-relprobe", $".{Path.PathSeparator}sub", null));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
            Directory.Delete(dir, recursive: true);
        }
    }

    [SkippableFact]
    public void PluginLocator_FindsExecutableOnPath_AndReturnsAbsolutePath()
    {
        Skip.If(OperatingSystem.IsWindows(), "planting an executable requires POSIX file modes");

        var dir = NewTempDir();

        try
        {
            var planted = PlantScript(dir, "age-plugin-pathprobe", "exit 0\n");
            var found = PluginLocator.Find("age-plugin-pathprobe", dir, null);

            Assert.Equal(planted, found);
            Assert.True(Path.IsPathRooted(found));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [SkippableFact]
    public void PluginLocator_IgnoresNonExecutableFile()
    {
        Skip.If(OperatingSystem.IsWindows(), "the execute bit is a POSIX concept");

        var dir = NewTempDir();

        try
        {
            var path = Path.Combine(dir, "age-plugin-notexec");
            File.WriteAllText(path, "#!/bin/sh\nexit 0\n");

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            Assert.Null(PluginLocator.Find("age-plugin-notexec", dir, null));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void PluginLocator_MissingBinary_ReturnsNull()
    {
        var dir = NewTempDir();

        try
        {
            Assert.Null(PluginLocator.Find("age-plugin-absent", dir, null));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
