using System.Runtime.CompilerServices;

namespace Age;

/// <summary>
/// Argument checks shared by the public entry points, in the shape of the BCL's own
/// <c>ThrowIfNull</c> / <c>ThrowIfNullOrEmpty</c> helpers.
/// </summary>
/// <remarks>
/// The BCL has no span equivalent — <see cref="ArgumentException.ThrowIfNullOrEmpty"/> takes a
/// <see cref="string"/> — and recipients and identities reach the API as
/// <c>params ReadOnlySpan&lt;T&gt;</c>, so the check lives here instead. Six entry points
/// repeated it verbatim, which is exactly how one of them ends up worded differently or missing
/// the guard altogether.
/// </remarks>
internal static class ArgumentGuard
{
    /// <summary>
    /// Throws when <paramref name="value"/> is empty. Encrypting to nobody, or decrypting with
    /// nothing, is a caller mistake rather than a format error: it can only ever fail, and
    /// failing at the entry point names the argument instead of surfacing later as a header
    /// with no stanzas or as <c>NoIdentityMatchException</c>.
    /// </summary>
    /// <param name="value">The recipients or identities supplied by the caller.</param>
    /// <param name="noun">
    /// Singular noun for the message, e.g. <c>"recipient"</c>. Passed explicitly rather than
    /// derived from <paramref name="paramName"/>, because "identities" does not depluralise by
    /// dropping a letter.
    /// </param>
    /// <param name="paramName">Captured from the call site; do not pass explicitly.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is empty.</exception>
    public static void ThrowIfEmpty<T>(
        ReadOnlySpan<T> value,
        string noun,
        [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        if (value.IsEmpty)
            throw new ArgumentException($"at least one {noun} is required", paramName);
    }
}
