namespace AgeSharp;

/// <summary>
/// How an age plugin talks to the user while it wraps or unwraps a file key: messages, values
/// and secrets it asks for, and confirmations. Every call names the plugin asking, so a host can
/// say which device wants a PIN when several plugins are in play.
/// </summary>
/// <remarks>
/// A callback that throws is answered to the plugin as a failure, as go-age answers one, and
/// the plugin decides what follows; usually the operation then fails with an
/// <see cref="AgePluginException"/>. Without callbacks at all, every request is answered as a
/// failure, as the plugin protocol specifies for a client with no user interface.
/// </remarks>
public interface IPluginCallbacks
{
    /// <summary>Shows a message from the plugin to the user.</summary>
    /// <param name="plugin">The plugin's name, as in <c>age-plugin-&lt;name&gt;</c>.</param>
    /// <param name="message">The message.</param>
    void DisplayMessage(string plugin, string message);

    /// <summary>Asks the user for a value that is not secret, echoed as they type.</summary>
    /// <param name="plugin">The plugin's name.</param>
    /// <param name="prompt">The plugin's prompt.</param>
    /// <returns>The value, or null if the user declined, which the plugin is told as a failure.</returns>
    string? RequestValue(string plugin, string prompt);

    /// <summary>Asks the user for a secret, such as a PIN or a passphrase, which is not echoed.</summary>
    /// <param name="plugin">The plugin's name.</param>
    /// <param name="prompt">The plugin's prompt.</param>
    /// <returns>
    /// The secret, or null if the user declined, which the plugin is told as a failure. The array
    /// is cleared once the plugin has it, so return a fresh one.
    /// </returns>
    /// <remarks>
    /// A <see cref="char"/>[] rather than a string, because a string cannot be cleared. A host
    /// reading from a console can fill the array directly and never hold the secret as a string.
    /// </remarks>
    char[]? RequestSecret(string plugin, string prompt);

    /// <summary>
    /// Asks the user to confirm. <paramref name="yes"/> and <paramref name="no"/> label the
    /// choices; <paramref name="no"/> is null when the plugin offers only one. Collect a simple
    /// choice rather than have the user type a label back.
    /// </summary>
    /// <param name="plugin">The plugin's name.</param>
    /// <param name="message">What to confirm.</param>
    /// <param name="yes">The label of the choice that confirms.</param>
    /// <param name="no">The label of the choice that does not, or null.</param>
    /// <returns>True if the user chose <paramref name="yes"/>.</returns>
    bool Confirm(string plugin, string message, string yes, string? no);

    /// <summary>
    /// Called once a plugin has kept the operation waiting for five seconds without asking for
    /// anything, as go-age's <c>WaitTimer</c> is: usually it waits for the user to touch a
    /// hardware key, which is worth saying. Called on another thread. Does nothing by default.
    /// </summary>
    /// <param name="plugin">The plugin's name.</param>
    void Waiting(string plugin)
    {
    }
}
