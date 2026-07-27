using Age.Crypto;
using Age.Plugin;
using Age.Recipients;
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

    // --- The positive half: a plugin genuinely on PATH runs, over a real pipe ---

    // The tests above prove a planted binary is *not* run. This proves the fix did not simply
    // break plugin support, and it is the only test that drives PluginConnection's real process
    // path: launching, the stanza framing over stdio, the stderr drain (C6) and Dispose (H7).
    [SkippableFact]
    public void PluginOnPath_IsLaunchedAndItsStanzaIsUsed()
    {
        Skip.If(OperatingSystem.IsWindows(), "planting an executable requires POSIX file modes");

        var dir = NewTempDir();
        var originalPath = Environment.GetEnvironmentVariable("PATH") ?? "";
        var name = "onpath" + Guid.NewGuid().ToString("N")[..8];
        var evidence = Path.Combine(dir, "RAN");

        // recipient-v1: answer wrap-file-key with one stanza, then done. Also writes a few KiB
        // to stderr, which deadlocked before C6 drained it.
        PlantScript(dir, $"age-plugin-{name}",
            $"touch '{evidence}'\n" +
            // A few KiB of stderr, exercising the C6 drain.
            "i=0; while [ $i -lt 200 ]; do echo 'plugin diagnostic noise' >&2; i=$((i+1)); done\n" +
            // Framing: a body ends at the first line shorter than 64 characters, so the 6-char
            // body needs no terminator. An empty body is a multiple of 64 and does need one,
            // which is why "done" is followed by a blank line and the stanza above is not.
            "printf '\\055> recipient-stanza 0 onpath-type\\nQUFBQQ\\n\\055> done\\n\\n'\n" +
            // Then hold stdin open until the client closes it, the way a real plugin does.
            // Backgrounding this would not work: POSIX sh redirects a background job's stdin
            // from /dev/null, so the drain would take EOF immediately and the script would exit
            // under the client's writes.
            "cat >/dev/null\n");

        try
        {
            // Prepend rather than replace: the child inherits this PATH, and the script needs
            // the ordinary tools (touch, cat) to be findable. Replacing it outright leaves the
            // plugin able to run but unable to do anything, which fails in a confusing way.
            Environment.SetEnvironmentVariable("PATH", $"{dir}{Path.PathSeparator}{originalPath}");

            var recipient = new PluginRecipient(Bech32.Encode($"age1{name}", [0x01, 0x02, 0x03]));
            var stanza = recipient.Wrap(new byte[16]);

            Assert.Equal("onpath-type", stanza.Type);
            Assert.True(File.Exists(evidence), "the plugin on PATH did not run");
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", originalPath);
            Directory.Delete(dir, recursive: true);
        }
    }
}
