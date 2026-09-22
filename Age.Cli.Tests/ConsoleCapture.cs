namespace Age.Cli.Tests;

/// <summary>
/// Redirects the process console for one test and restores it afterwards. Safe only because this
/// assembly runs its tests one at a time: the console is process-wide.
/// </summary>
internal sealed class ConsoleCapture : IDisposable
{
    private readonly TextReader _in = Console.In;
    private readonly TextWriter _out = Console.Out;
    private readonly TextWriter _error = Console.Error;
    private readonly StringWriter _capturedOut = new();
    private readonly StringWriter _capturedError = new();

    public ConsoleCapture(string input = "")
    {
        Console.SetIn(new StringReader(input));
        Console.SetOut(_capturedOut);
        Console.SetError(_capturedError);
    }

    public string Out => _capturedOut.ToString();
    public string Error => _capturedError.ToString();

    public void Dispose()
    {
        Console.SetIn(_in);
        Console.SetOut(_out);
        Console.SetError(_error);
    }
}
