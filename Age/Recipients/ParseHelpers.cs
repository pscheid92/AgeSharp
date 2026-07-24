using System.Diagnostics.CodeAnalysis;

namespace Age.Recipients;

internal static class ParseHelpers
{
    /// <summary>
    /// The TryParse contract shared by every key type: null input → false,
    /// <see cref="AgeFormatException"/> from <paramref name="parse"/> → false,
    /// anything else propagates (an unexpected exception is a bug signal, not
    /// a malformed input). Method-group conversions to <paramref name="parse"/>
    /// are cached by the compiler, so forwarding here does not allocate.
    /// </summary>
    internal static bool TryParse<T>(string? s, Func<string, T> parse, [MaybeNullWhen(false)] out T result)
        where T : class
    {
        if (s is not null)
        {
            try
            {
                result = parse(s);
                return true;
            }
            catch (AgeFormatException)
            {
            }
        }

        result = null;
        return false;
    }
}
