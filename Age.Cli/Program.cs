namespace Age.Cli;

internal static class Program
{
    static int Main(string[] args)
    {
        var processName = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "age");

        if (processName.Contains("keygen", StringComparison.OrdinalIgnoreCase)
            || (args.Length > 0 && args[0] == "keygen"))
        {
            var keygenArgs = args.Length > 0 && args[0] == "keygen" ? args[1..] : args;
            return KeygenCommand.Run(keygenArgs);
        }

        if (args.Length > 0 && args[0] == "inspect")
        {
            return InspectCommand.Run(args[1..]);
        }

        return AgeCommand.Run(args);
    }
}
