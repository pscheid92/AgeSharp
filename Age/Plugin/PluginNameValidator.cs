namespace Age.Plugin;

/// <summary>
/// Validation for age plugin names. A plugin name becomes part of the
/// <c>age-plugin-&lt;name&gt;</c> executable that is launched via <c>Process.Start</c>,
/// so it must never contain a path separator (or any other character that could turn
/// that filename into a relative or absolute path). The allowed set mirrors the
/// reference implementation's <c>validPluginName</c>.
/// </summary>
internal static class PluginNameValidator
{
    private static bool IsAllowed(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.' or '_';

    public static bool IsValid(string name)
    {
        if (name.Length == 0)
            return false;

        foreach (var c in name)
        {
            if (!IsAllowed(c))
                return false;
        }

        return true;
    }

    /// <summary>Returns <paramref name="name"/> if valid, otherwise throws <see cref="AgeFormatException"/>.</summary>
    public static string Validate(string name) =>
        IsValid(name)
            ? name
            : throw new AgeFormatException($"invalid plugin name: '{name}'");
}
