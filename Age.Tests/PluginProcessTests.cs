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

    /// <summary>
    /// Best-effort cleanup. On Windows a just-written executable is often still held open by the
    /// virus scanner, and a temp directory the OS will reclaim anyway must not decide whether a
    /// test passed — the assertions have already run by the time this is reached.
    /// </summary>
    private static void TryDeleteTempDir(string dir)
    {
        try
        {
            Directory.Delete(dir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left for the OS to reclaim.
        }
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

    /// <summary>
    /// Plants a fake <c>age-plugin-&lt;name&gt;</c> that records having run, answers recipient-v1
    /// with one stanza, writes a few KiB to stderr, then holds stdin open until the client closes
    /// it — the lifecycle a real plugin has.
    /// </summary>
    /// <remarks>
    /// Cross-platform on purpose. S1 matters most on Windows, where <c>CreateProcess</c> searches
    /// the application directory and the working directory by documented design, so skipping the
    /// process tests there would leave the more dangerous platform unverified end to end.
    /// </remarks>
    private static string PlantFakePlugin(string directory, string pluginName, string stanzaType, string evidence)
    {
        if (OperatingSystem.IsWindows())
        {
            // `^` escapes `>` for cmd; `echo.` emits a blank line; `more` drains stdin to EOF.
            var cmd = Path.Combine(directory, $"age-plugin-{pluginName}.CMD");
            File.WriteAllText(cmd,
                "@echo off\r\n" +
                $"echo ran>\"{evidence}\"\r\n" +
                "for /L %%i in (1,1,200) do echo plugin diagnostic noise 1>&2\r\n" +
                $"echo -^> recipient-stanza 0 {stanzaType}\r\n" +
                "echo QUFBQQ\r\n" +
                "echo -^> done\r\n" +
                "echo.\r\n" +
                "more >nul\r\n");
            return cmd;
        }

        return PlantScript(directory, $"age-plugin-{pluginName}",
            $"touch '{evidence}'\n" +
            "i=0; while [ $i -lt 200 ]; do echo 'plugin diagnostic noise' >&2; i=$((i+1)); done\n" +
            // A body ends at the first line under 64 characters, so the 6-char body needs no
            // terminator; an empty body is a multiple of 64 and does, hence the blank after done.
            $"printf '\\055> recipient-stanza 0 {stanzaType}\\nQUFBQQ\\n\\055> done\\n\\n'\n" +
            // Foreground: POSIX sh redirects a background job's stdin from /dev/null, so a
            // backgrounded drain would take EOF at once and the script would exit under the
            // client's writes.
            "cat >/dev/null\n");
    }

    // --- S1: plugin binaries must never be resolved from the current working directory ---

    // Runs on every platform, including Windows — where CreateProcess searches the working
    // directory by design and this is therefore the most important place to assert it does not.
    [Fact]
    public void PluginConnection_NeverExecutesBinaryFromCurrentDirectory()
    {
        var dir = NewTempDir();
        var marker = Path.Combine(dir, "EXECUTED");

        // The plugin name has to be one nothing else could plausibly provide, so a hit
        // can only have come from the current directory.
        var name = "cwdprobe" + Guid.NewGuid().ToString("N")[..8];
        PlantFakePlugin(dir, name, "cwd-type", marker);

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

        TryDeleteTempDir(dir);
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
            TryDeleteTempDir(dir);
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
            TryDeleteTempDir(dir);
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
            TryDeleteTempDir(dir);
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
            TryDeleteTempDir(dir);
        }
    }

    // --- The positive half: a plugin genuinely on PATH runs, over a real pipe ---

    // The tests above prove a planted binary is *not* run. This proves the fix did not simply
    // break plugin support, and it is the only test that drives PluginConnection's real process
    // path: launching, the stanza framing over stdio, the stderr drain (C6) and Dispose (H7).
    // C6's other half: draining stderr is only useful if the diagnostics reach the caller. When a
    // plugin dies without answering, its stderr is the sole account of why — previously discarded.
    [Fact]
    public void WhenAPluginDies_ItsStderrIsQuotedInTheException()
    {
        var dir = NewTempDir();
        var originalPath = Environment.GetEnvironmentVariable("PATH") ?? "";
        var name = "dying" + Guid.NewGuid().ToString("N")[..8];

        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(Path.Combine(dir, $"age-plugin-{name}.CMD"),
                "@echo off\r\necho catastrophic plugin failure 1>&2\r\nexit /b 1\r\n");
        }
        else
        {
            PlantScript(dir, $"age-plugin-{name}",
                "echo 'catastrophic plugin failure' >&2\nexit 1\n");
        }

        try
        {
            Environment.SetEnvironmentVariable("PATH", $"{dir}{Path.PathSeparator}{originalPath}");

            var recipient = new PluginRecipient(Bech32.Encode($"age1{name}", [0x01, 0x02, 0x03]));
            // Which side notices the death is a timing accident — the client writes its whole
            // request before reading, so a fast exit breaks the write and a slow one breaks the
            // read. Both must report as AgePluginException, with the stderr attached.
            var ex = Assert.Throws<AgePluginException>(() => recipient.Wrap(new byte[16]));

            Assert.Contains("catastrophic plugin failure", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", originalPath);
            TryDeleteTempDir(dir);
        }
    }

    [Fact]
    public void PluginOnPath_IsLaunchedAndItsStanzaIsUsed()
    {
        var dir = NewTempDir();
        var originalPath = Environment.GetEnvironmentVariable("PATH") ?? "";
        var name = "onpath" + Guid.NewGuid().ToString("N")[..8];
        var evidence = Path.Combine(dir, "RAN");

        PlantFakePlugin(dir, name, "onpath-type", evidence);

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
            TryDeleteTempDir(dir);
        }
    }
}
