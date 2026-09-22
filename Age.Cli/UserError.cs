namespace Age.Cli;

/// <summary>
/// Sorts a failure into the user's to fix — a malformed file, a wrong key, a path that does not
/// exist or cannot be written — and a bug in AgeSharp, which is anything else.
/// </summary>
internal static class UserError
{
    /// <summary>The message to show the user, or null when the failure is a bug.</summary>
    public static string? Describe(Exception ex) => ex switch
    {
        AgeException or FormatException => ex.Message,

        // Checked before IOException, which it derives from, to name the path in age's words.
        FileNotFoundException notFound => $"no such file: {notFound.FileName}",

        // Missing directories, full disks, permissions: the OS's message says what went wrong.
        IOException or UnauthorizedAccessException => ex.Message,

        _ => null,
    };
}
