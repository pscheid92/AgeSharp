namespace Age.Cli;

/// <summary>
/// The process's standard input and output as a command sees them, and whether output goes to a
/// terminal. Commands take these rather than reaching for <see cref="Console"/>, so tests can put a
/// terminal or a pipe where the real ones would be.
/// </summary>
internal sealed record StandardStreams(Func<Stream> OpenInput, Func<Stream> OpenOutput, bool OutputIsTerminal)
{
    public static StandardStreams FromConsole() =>
        new(Console.OpenStandardInput, Console.OpenStandardOutput, OutputIsTerminal: !Console.IsOutputRedirected);
}
