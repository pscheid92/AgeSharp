using Age.Recipients;

namespace Age.Cli;

internal static class KeygenCommand
{
    public static int Run(string[] args)
    {
        var outputPath = (string?)null;
        var convertToPublic = false;
        var postQuantum = false;
        string? inputPath = null;

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
                    convertToPublic = true;
                    break;
                case "-pq" or "--pq":
                    postQuantum = true;
                    break;
                default:
                    if (args[i].StartsWith('-'))
                    {
                        Error($"unknown option: {args[i]}");
                        return 1;
                    }
                    if (inputPath != null)
                    {
                        Error($"unexpected argument: {args[i]}");
                        return 1;
                    }
                    inputPath = args[i];
                    break;
            }
        }

        try
        {
            if (convertToPublic)
                return ConvertToPublic(inputPath, outputPath);

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
            if (File.Exists(outputPath))
            {
                Error($"output file already exists: {outputPath}");
                return 1;
            }
            File.WriteAllText(outputPath, output);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(outputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Console.Error.WriteLine($"Public key: {publicKey}");
        }
        else
        {
            if (Console.IsOutputRedirected)
            {
                Console.Error.WriteLine("age-keygen: warning: writing secret key to a world-readable file");
                Console.Error.WriteLine($"Public key: {publicKey}");
            }
            Console.Write(output);
        }

        return 0;
    }

    private static int ConvertToPublic(string? inputPath, string? outputPath)
    {
        string text;
        if (inputPath is not null)
            text = File.ReadAllText(inputPath);
        else
            text = Console.In.ReadToEnd();

        var recipients = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;

            if (trimmed.StartsWith("AGE-SECRET-KEY-PQ-"))
            {
                using var identity = MlKem768X25519Identity.Parse(trimmed);
                recipients.Add(identity.Recipient.ToString());
            }
            else if (trimmed.StartsWith("AGE-SECRET-KEY-"))
            {
                using var identity = X25519Identity.Parse(trimmed);
                recipients.Add(identity.Recipient.ToString());
            }
            else
            {
                Error($"unsupported identity type");
                return 1;
            }
        }

        if (recipients.Count == 0)
        {
            Error("no identity found");
            return 1;
        }

        using var output = outputPath is not null ? File.CreateText(outputPath) : Console.Out;
        foreach (var r in recipients)
            output.WriteLine(r);

        return 0;
    }

    private static void Error(string message)
    {
        Console.Error.WriteLine($"age-keygen: {message}");
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("""
            Usage:
                age-keygen [-pq] [-o OUTPUT]
                age-keygen -y [-o OUTPUT] [INPUT]

            Options:
                -pq                       Generate a post-quantum hybrid ML-KEM-768 + X25519 key pair.
                                          (This might become the default in the future.)
                -o, --output OUTPUT       Write the result to the file at path OUTPUT.
                -y                        Convert an identity file to a recipients file.

            age-keygen generates a new native X25519 or, with the -pq flag, post-quantum
            hybrid ML-KEM-768 + X25519 key pair, and outputs it to standard output or to
            the OUTPUT file.

            If an OUTPUT file is specified, the public key is printed to standard error.
            If OUTPUT already exists, it is not overwritten.

            In -y mode, age-keygen reads an identity file from INPUT or from standard
            input and writes the corresponding recipient(s) to OUTPUT or to standard
            output, one per line, with no comments.

            Examples:

                $ age-keygen
                # created: 2021-01-02T15:30:45+01:00
                # public key: age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z
                AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9

                $ age-keygen -pq
                # created: 2025-11-17T12:15:17+01:00
                # public key: age1pq1pd[... 1950 more characters ...]
                AGE-SECRET-KEY-PQ-1XXC4XS9DXHZ6TREKQTT3XECY8VNNU7GJ83C3Y49D0GZ3ZUME4JWS6QC3EF

                $ age-keygen -o key.txt
                Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

                $ age-keygen -y key.txt
                age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
            """);
    }
}
