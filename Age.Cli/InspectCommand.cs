using Age;
using Age.Format;

namespace Age.Cli;

internal static class InspectCommand
{
    public static int Run(string[] args)
    {
        string? filePath = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return 0;
                default:
                    if (args[i].StartsWith('-'))
                    {
                        Error($"unknown option: {args[i]}");
                        return 1;
                    }
                    if (filePath != null)
                    {
                        Error("too many arguments");
                        return 1;
                    }
                    filePath = args[i];
                    break;
            }
        }

        try
        {
            Stream rawInput;
            string displayName;
            if (filePath != null)
            {
                rawInput = File.OpenRead(filePath);
                displayName = filePath;
            }
            else
            {
                rawInput = Console.OpenStandardInput();
                displayName = "(stdin)";
            }

            using (rawInput)
            {
                // Buffer into a seekable stream if needed (for armor detection)
                Stream input;
                if (!rawInput.CanSeek)
                {
                    var ms = new MemoryStream();
                    rawInput.CopyTo(ms);
                    ms.Position = 0;
                    input = ms;
                }
                else
                {
                    input = rawInput;
                }

                var header = AgeHeader.Parse(input);

                Console.WriteLine($"File: {displayName}");
                Console.WriteLine($"Armored: {(header.IsArmored ? "yes" : "no")}");
                Console.WriteLine($"Recipients: {header.RecipientCount}");

                for (int i = 0; i < header.Recipients.Count; i++)
                {
                    var stanza = header.Recipients[i];
                    string detail = FormatStanzaDetail(stanza);
                    Console.WriteLine($"  [{i}] {detail}");
                }
            }

            return 0;
        }
        catch (AgeException ex)
        {
            Error(ex.Message);
            return 1;
        }
        catch (FileNotFoundException)
        {
            Error($"no such file: {filePath}");
            return 1;
        }
    }

    private static string FormatStanzaDetail(Stanza stanza)
    {
        return stanza.Type switch
        {
            "X25519" => FormatX25519(stanza),
            "scrypt" => FormatScrypt(stanza),
            "ssh-ed25519" => FormatSshEd25519(stanza),
            "ssh-rsa" => FormatSshRsa(stanza),
            "mlkem768x25519" => FormatMlKem(stanza),
            _ => FormatPlugin(stanza)
        };
    }

    private static string FormatX25519(Stanza stanza)
    {
        var share = stanza.Args.Length > 0 ? Truncate(stanza.Args[0], 10) : "?";
        return $"X25519 (ephemeral share: {share})";
    }

    private static string FormatScrypt(Stanza stanza)
    {
        var salt = stanza.Args.Length > 0 ? Truncate(stanza.Args[0], 10) : "?";
        var logN = stanza.Args.Length > 1 ? stanza.Args[1] : "?";
        return $"scrypt (salt: {salt}, log2(N): {logN})";
    }

    private static string FormatSshEd25519(Stanza stanza)
    {
        var tag = stanza.Args.Length > 0 ? Truncate(stanza.Args[0], 10) : "?";
        return $"ssh-ed25519 (key tag: {tag})";
    }

    private static string FormatSshRsa(Stanza stanza)
    {
        var tag = stanza.Args.Length > 0 ? Truncate(stanza.Args[0], 10) : "?";
        return $"ssh-rsa (key tag: {tag})";
    }

    private static string FormatMlKem(Stanza stanza)
    {
        var share = stanza.Args.Length > 0 ? Truncate(stanza.Args[0], 10) : "?";
        return $"mlkem768x25519 (ephemeral share: {share})";
    }

    private static string FormatPlugin(Stanza stanza)
    {
        var argsStr = stanza.Args.Length > 0
            ? string.Join(", ", stanza.Args.Select(a => Truncate(a, 10)))
            : "none";
        return $"{stanza.Type} (args: {argsStr})";
    }

    private static string Truncate(string s, int maxLen)
    {
        return s.Length <= maxLen ? s : s[..maxLen] + "…";
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("Usage: age inspect [FILE]");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Inspect an age-encrypted file without decrypting it.");
        Console.Error.WriteLine("Reads from stdin if no file is specified.");
    }

    private static void Error(string msg)
    {
        Console.Error.WriteLine($"age inspect: {msg}");
    }
}
