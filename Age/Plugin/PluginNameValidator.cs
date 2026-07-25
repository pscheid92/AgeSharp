namespace AgeSharp;

// A plugin name becomes an executable name (age-plugin-<name>), so it is validated before
// it can reach a process start.
internal static class PluginNameValidator
{
    private static bool IsAllowed(char c)
    {
        return char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.' or '_';
    }

    public static bool IsValid(string name)
    {
        if (name.Length == 0)
            return false;

        foreach (var c in name)
            if (!IsAllowed(c))
                return false;

        return true;
    }

    public static string Validate(string name)
    {
        return IsValid(name)
            ? name
            : throw new AgeFormatException($"invalid plugin name: '{name}'");
    }
}