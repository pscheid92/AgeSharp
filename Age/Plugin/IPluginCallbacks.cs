namespace Age.Plugin;

public interface IPluginCallbacks
{
    void DisplayMessage(string message);
    string RequestValue(string prompt, bool secret);
    bool Confirm(string message, string yes, string? no);
}
