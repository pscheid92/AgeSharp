using Age.Recipients;

namespace Age.Cli;

internal static class KeygenCommand
{
    public static int Run(string[] args)
    {
        var outputPath = (string?)null;
        var convertPath = (string?)null;
        var postQuantum = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return 0;
                case "-o" or "--output":
                    if (++i >= args.Length)
                    {
                        Error("flag needs an argument: -o");
                        return 1;
                    }
                    outputPath = args[i];
                    break;
                case "-y":
                    if (++i >= args.Length)
                    {
                        Error("flag needs an argument: -y");
                        return 1;
                    }
                    convertPath = args[i];
                    break;
                case "--pq":
                    postQuantum = true;
                    break;
                default:
                    Error($"unknown option: {args[i]}");
                    return 1;
            }
        }

        try
        {
            if (convertPath is not null)
                return ConvertToPublic(convertPath);

            return Generate(outputPath, postQuantum);
        }
        catch (Exception ex) when (ex is AgeException or FormatException)
        {
            Error(ex.Message);
            return 1;
        }
        catch (Exception ex)
        {
            Error($"internal error: {ex.Message}");
            Error($"This is a bug. Please report it at https://github.com/pscheid92/AgeSharp/issues");
            return 1;
        }
    }

    private static int Generate(string? outputPath, bool postQuantum)
    {
        string publicKey;
        string secretKey;

        if (postQuantum)
        {
            using var identity = AgeKeygen.GeneratePq();
            publicKey = identity.Recipient.ToString();
            secretKey = identity.ToString();
        }
        else
        {
            using var identity = AgeKeygen.Generate();
            publicKey = identity.Recipient.ToString();
            secretKey = identity.ToString();
        }

        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var output = $"# created: {timestamp}\n# public key: {publicKey}\n{secretKey}\n";

        if (outputPath is not null)
        {
            File.WriteAllText(outputPath, output);
            Console.Error.WriteLine($"Public key: {publicKey}");
        }
        else
        {
            if (Console.IsErrorRedirected == false)
                Console.Error.WriteLine($"Public key: {publicKey}");
            Console.Write(output);
        }

        return 0;
    }

    private static int ConvertToPublic(string path)
    {
        var text = File.ReadAllText(path);

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;

            if (trimmed.StartsWith("AGE-SECRET-KEY-PQ-"))
            {
                using var identity = MlKem768X25519Identity.Parse(trimmed);
                Console.WriteLine(identity.Recipient);
                return 0;
            }

            if (trimmed.StartsWith("AGE-SECRET-KEY-"))
            {
                using var identity = X25519Identity.Parse(trimmed);
                Console.WriteLine(identity.Recipient);
                return 0;
            }

            Error($"unsupported identity type in file: {path}");
            return 1;
        }

        Error($"no identity found in file: {path}");
        return 1;
    }

    private static void Error(string message)
    {
        Console.Error.WriteLine($"age-keygen: {message}");
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("""
            Usage:
                age-keygen [-o OUTPUT]
                age-keygen --pq [-o OUTPUT]
                age-keygen -y IDENTITY_FILE

            Options:
                -o, --output PATH   Write identity to PATH (default: stdout)
                -y IDENTITY_FILE    Convert identity file to public key
                    --pq            Generate ML-KEM-768-X25519 (post-quantum) key
                -h, --help          Print this help
            """);
    }
}
