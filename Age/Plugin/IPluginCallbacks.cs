namespace AgeSharp;

/// <summary>
/// User-interaction callbacks invoked when an age plugin needs to display a message
/// or request input from the user during an operation.
/// </summary>
public interface IPluginCallbacks
{
    /// <summary>Displays an informational message from the plugin to the user.</summary>
    void DisplayMessage(string message);

    /// <summary>Requests a public value from the user, echoed as they type.</summary>
    /// <param name="prompt">The plugin's prompt.</param>
    string RequestValue(string prompt);

    /// <summary>
    /// Requests a secret from the user, such as a PIN or passphrase, which should not be echoed.
    /// </summary>
    /// <param name="prompt">The plugin's prompt.</param>
    /// <returns>
    /// The secret, or null if there is none (the user cancelled), which the plugin is told as a
    /// failure. The library zeroes the array once the plugin has it, so return a fresh one.
    /// </returns>
    /// <remarks>
    /// Separate from <see cref="RequestValue"/>, and a <see cref="char"/>[] rather than a string,
    /// because a string cannot be cleared. A host reading from a console can fill the array
    /// directly and never hold the secret as a string.
    /// </remarks>
    char[]? RequestSecret(string prompt);

    /// <summary>
    /// Asks the user to confirm an action. <paramref name="yes"/> and <paramref name="no"/>
    /// are display labels for the choices (already decoded from the wire encoding);
    /// <paramref name="no"/> is null when the plugin offers a single option.
    /// Implementations should collect a simple yes/no decision rather than require
    /// the user to type a label back. Returns true if the user chose the yes option.
    /// </summary>
    bool Confirm(string message, string yes, string? no);
}
