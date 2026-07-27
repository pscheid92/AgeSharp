using System.Runtime.CompilerServices;

namespace Age;

/// <summary>
/// Adds a span-shaped emptiness check to <see cref="ArgumentException"/>, alongside the BCL's own
/// <see cref="ArgumentException.ThrowIfNullOrEmpty"/>.
/// </summary>
/// <remarks>
/// A C# 14 static extension member, so it is called as <c>ArgumentException.ThrowIfEmpty(...)</c>
/// and reads like the framework guard it sits beside. The BCL has no span form — its own overload
/// takes a <see cref="string"/> — while recipients and identities reach this library's entry
/// points as <c>params ReadOnlySpan&lt;T&gt;</c>.
/// <para>
/// Internal to this assembly: extending a framework type is a liberty worth taking for six
/// call sites inside one library, not for anything a consumer would see.
/// </para>
/// </remarks>
internal static class ArgumentExceptionExtensions
{
    extension(ArgumentException)
    {
        /// <summary>
        /// Throws when <paramref name="value"/> is empty. Encrypting to nobody, or decrypting
        /// with nothing, is a caller mistake rather than a format error: it can only ever fail,
        /// and failing at the entry point names the argument instead of surfacing later as a
        /// header with no stanzas or as <see cref="NoIdentityMatchException"/>.
        /// </summary>
        /// <param name="value">The recipients or identities supplied by the caller.</param>
        /// <param name="noun">
        /// Singular noun for the message, e.g. <c>"recipient"</c>. Passed explicitly rather than
        /// derived from <paramref name="paramName"/>, because "identities" does not depluralise
        /// by dropping a letter.
        /// </param>
        /// <param name="paramName">Captured from the call site; do not pass explicitly.</param>
        /// <exception cref="ArgumentException"><paramref name="value"/> is empty.</exception>
        public static void ThrowIfEmpty<T>(ReadOnlySpan<T> value, string noun, [CallerArgumentExpression(nameof(value))] string? paramName = null)
        {
            if (value.IsEmpty)
                throw new ArgumentException($"at least one {noun} is required", paramName);
        }
    }
}
