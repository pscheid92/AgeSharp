namespace AgeSharp;

/// <summary>
///     User-interaction callbacks invoked when an age plugin needs to display a message
///     or request input from the user during an operation.
/// </summary>
public interface IPluginCallbacks
{
    /// <summary>Displays an informational message from the plugin to the user.</summary>
    void DisplayMessage(string message);

    /// <summary>Requests a public value from the user, echoed as they type.</summary>
    /// <param name="prompt">The plugin's prompt text.</param>
    string RequestValue(string prompt);

    /// <summary>
    ///     Requests a secret from the user — a PIN or passphrase — which should not be echoed.
    /// </summary>
    /// <param name="prompt">The plugin's prompt text.</param>
    /// <returns>
    ///     The secret. The library zeroes this array once it has been sent to the plugin, so
    ///     return a fresh one rather than a shared buffer.
    /// </returns>
    /// <remarks>
    ///     Separate from <see cref="RequestValue" />, and returning <see cref="char" />[] rather
    ///     than a string, because a string cannot be cleared — the same reason
    ///     <see cref="Passphrase" /> takes a <see cref="ReadOnlySpan{T}" />. A host reading from a
    ///     console can fill a <see cref="char" />[] directly and keep the secret off the heap
    ///     entirely; one that cannot is no worse off than before.
    /// </remarks>
    char[] RequestSecret(string prompt);

    /// <summary>
    ///     Asks the user to confirm an action. <paramref name="yes" /> and <paramref name="no" />
    ///     are display labels for the choices (already decoded from the wire encoding);
    ///     <paramref name="no" /> is null when the plugin offers a single option.
    ///     Implementations should collect a simple yes/no decision rather than require
    ///     the user to type a label back. Returns true if the user chose the yes option.
    /// </summary>
    bool Confirm(string message, string yes, string? no);
}