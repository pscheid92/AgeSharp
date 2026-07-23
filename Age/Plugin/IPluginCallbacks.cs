namespace Age.Plugin;

/// <summary>
/// User-interaction callbacks invoked when an age plugin needs to display a message
/// or request input from the user during an operation.
/// </summary>
public interface IPluginCallbacks
{
    /// <summary>Displays an informational message from the plugin to the user.</summary>
    void DisplayMessage(string message);

    /// <summary>
    /// Requests a value from the user, such as a PIN or passphrase.
    /// When <paramref name="secret"/> is true, the input should not be echoed.
    /// </summary>
    string RequestValue(string prompt, bool secret);

    /// <summary>
    /// Asks the user to confirm an action. <paramref name="yes"/> and <paramref name="no"/>
    /// are display labels for the choices (already decoded from the wire encoding);
    /// <paramref name="no"/> is null when the plugin offers a single option.
    /// Implementations should collect a simple yes/no decision rather than require
    /// the user to type a label back. Returns true if the user chose the yes option.
    /// </summary>
    bool Confirm(string message, string yes, string? no);
}
