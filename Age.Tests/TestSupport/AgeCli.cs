namespace Age.Tests;

/// <summary>
/// Locates the reference <c>age</c> / <c>age-keygen</c> CLI binaries used by the interop
/// tests by searching <c>PATH</c>. CI installs age onto PATH explicitly; local shells get it
/// via Homebrew's <c>shellenv</c>. When age is not on PATH the tests skip cleanly rather than
/// falsely passing.
/// </summary>
internal static class AgeCli
{
    public static string? AgePath { get; } = Find("age");
    public static string? AgeKeygenPath { get; } = Find("age-keygen");

    public static bool Available => AgePath is not null;
    public static bool KeygenAvailable => AgeKeygenPath is not null;

    private static string? Find(string name)
    {
        var fileName = OperatingSystem.IsWindows() ? name + ".exe" : name;

        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = Path.Combine(dir, fileName);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
