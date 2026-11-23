namespace AgeSharp;

/// <summary>
/// Resolves an <c>age-plugin-&lt;name&gt;</c> binary to an absolute path, searching
/// <c>PATH</c> and nothing else.
/// </summary>
/// <remarks>
/// The age-plugin spec is explicit: "Paths relative to the current working directory
/// MUST NOT be searched, even on platforms or systems where this is the default."
/// Handing a bare file name to <see cref="System.Diagnostics.Process"/> does exactly
/// that on .NET — even with <c>UseShellExecute = false</c> — so resolution is done here
/// instead, and only an absolute result is ever handed to the process launcher.
/// </remarks>
internal static class PluginLocator
{
    /// <summary>
    /// Returns the absolute path of <paramref name="binaryName"/> on <c>PATH</c>,
    /// or null when it is not there.
    /// </summary>
    public static string? Find(string binaryName) =>
        Find(binaryName, Environment.GetEnvironmentVariable("PATH"), Environment.GetEnvironmentVariable("PATHEXT"));

    /// <summary>Testable core of <see cref="Find(string)"/> with the environment injected.</summary>
    internal static string? Find(string binaryName, string? searchPath, string? pathExt)
    {
        var windows = OperatingSystem.IsWindows();

        foreach (var directory in Directories(searchPath, windows))
        {
            foreach (var candidate in Candidates(directory, binaryName, pathExt, windows))
            {
                if (IsExecutableFile(candidate))
                    return candidate;
            }
        }

        return null;
    }

    /// <summary>
    /// The PATH entries that may be searched: the absolute ones. An empty entry means "the
    /// current directory" on most shells, and a relative one resolves against it, both of which
    /// the spec forbids. On Windows that includes a drive without a separator (<c>C:bin</c>) and
    /// a separator without a drive (<c>\bin</c>), so only fully qualified entries count; and an
    /// entry may be quoted, to hold a <c>;</c>, as Go's <c>filepath.SplitList</c> reads it.
    /// </summary>
    internal static IEnumerable<string> Directories(string? searchPath, bool windows)
    {
        if (string.IsNullOrEmpty(searchPath))
            return [];

        IEnumerable<string> entries = windows ? SplitWindowsPath(searchPath) : searchPath.Split(':');

        return entries.Where(entry => windows ? IsFullyQualifiedOnWindows(entry) : entry.StartsWith('/'));
    }

    // ';' separates entries except inside double quotes, which are removed.
    private static List<string> SplitWindowsPath(string searchPath)
    {
        var entries = new List<string>();
        var entry = new System.Text.StringBuilder();
        var quoted = false;

        foreach (var c in searchPath)
        {
            if (c == '"')
                quoted = !quoted;
            else if (c == ';' && !quoted)
            {
                entries.Add(entry.ToString());
                entry.Clear();
            }
            else
                entry.Append(c);
        }

        entries.Add(entry.ToString());
        return entries;
    }

    // A drive and a separator (C:\, C:/), or a UNC path (\\server\share): what Windows resolves
    // without a working directory.
    private static bool IsFullyQualifiedOnWindows(string entry) =>
        entry.Length >= 3 && char.IsAsciiLetter(entry[0]) && entry[1] == ':' && entry[2] is '\\' or '/'
        || entry.Length >= 2 && entry[0] is '\\' or '/' && entry[1] is '\\' or '/';

    /// <summary>The paths tried in one PATH directory, in order.</summary>
    internal static IEnumerable<string> Candidates(string directory, string binaryName, string? pathExt, bool windows)
    {
        var basePath = Path.Combine(directory, binaryName);

        // On Windows the bare name is tried only when it already has an extension, as Go's
        // exec.LookPath (which go-age uses) does: an extensionless file is not executable there,
        // and trying it first let a stray one shadow the .exe beside it.
        if (!windows || HasExtension(binaryName))
            yield return basePath;

        if (!windows)
            yield break;

        // On Windows an extensionless name is not executable; PATHEXT lists the suffixes
        // the shell would have tried.
        var extensions = string.IsNullOrEmpty(pathExt) ? ".COM;.EXE;.BAT;.CMD" : pathExt;

        foreach (var extension in extensions.Split(';'))
        {
            if (extension.Length > 0)
                yield return basePath + extension;
        }
    }

    private static bool HasExtension(string name) =>
        name.LastIndexOf('.') > name.LastIndexOfAny([':', '\\', '/']);

    private static bool IsExecutableFile(string path)
    {
        if (!File.Exists(path))
            return false;

        if (OperatingSystem.IsWindows())
            return true;

        try
        {
            const UnixFileMode executable =
                UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

            return (File.GetUnixFileMode(path) & executable) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
