using Age.Plugin;

namespace Age.Cli;

/// <summary>
/// Answers a plugin's questions — PINs, values, confirmations — on the terminal, never on
/// standard input, which may be the data being decrypted.
/// </summary>
/// <param name="openTerminal">Opens the terminal to ask on; each question opens and closes it.</param>
internal sealed class CliPluginCallbacks(Func<ITerminal> openTerminal) : IPluginCallbacks
{
    public void DisplayMessage(string message) =>
        Console.Error.WriteLine(message);

    public string RequestValue(string prompt, bool secret) =>
        Ask(prompt + ": ", secret);

    public bool Confirm(string message, string yes, string? no)
    {
        var options = no is not null ? $"[y: {yes} / n: {no}]" : $"[y: {yes}]";
        var prompt = $"{message} {options} (y/N): ";

        while (true)
        {
            switch (Ask(prompt, secret: false).Trim().ToLowerInvariant())
            {
                case "" or "n" or "no":
                    return false;
                case "y" or "yes":
                    return true;
            }

            prompt = "Please answer y or n (y/N): ";
        }
    }

    private string Ask(string prompt, bool secret)
    {
        using var terminal = openTerminal();
        return terminal.ReadLine(prompt, secret);
    }
}
