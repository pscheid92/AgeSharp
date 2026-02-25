using Age.Recipients;

namespace Age.Cli;

internal static class KeygenCommand
{
    public static int Run(string[] args)
    {
        try
        {
            return Execute(args);
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

    private record KeygenArgs(string? OutputPath, bool ConvertToPublic, bool PostQuantum, string? InputPath);

    private static int Execute(string[] args)
    {
        var parsed = ParseArgs(args);
        if (parsed is null)
            return 0;

        return parsed.ConvertToPublic
            ? ConvertToPublic(parsed.InputPath, parsed.OutputPath)
            : Generate(parsed.OutputPath, parsed.PostQuantum);
    }

    private static KeygenArgs? ParseArgs(string[] args)
    {
        var outputPath = (string?)null;
        var convertToPublic = false;
        var postQuantum = false;
        string? inputPath = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return null;
                case "-o" or "--output":
                    outputPath = ReadRequiredArg(args, ref i, "-o");
                    break;
                case "-y":
                    convertToPublic = true;
                    break;
                case "-pq" or "--pq":
                    postQuantum = true;
                    break;
                default:
                    inputPath = ParsePositionalArg(args[i], inputPath);
                    break;
            }
        }

        return new KeygenArgs(outputPath, convertToPublic, postQuantum, inputPath);
    }

    private static string IdentityToPublicKey(string line)
    {
        if (line.StartsWith("AGE-SECRET-KEY-PQ-"))
        {
            using var identity = MlKem768X25519Identity.Parse(line);
            return identity.Recipient.ToString();
        }

        if (line.StartsWith("AGE-SECRET-KEY-"))
        {
            using var identity = X25519Identity.Parse(line);
            return identity.Recipient.ToString();
        }

        throw new AgeException("unsupported identity type");
    }

    private static string ReadRequiredArg(string[] args, ref int i, string flag) =>
        ++i < args.Length ? args[i] : throw new AgeException($"flag requires an argument: {flag}");

    private static string ParsePositionalArg(string arg, string? current)
    {
        if (arg.StartsWith('-'))
            throw new AgeException($"unknown option: {arg}");

        return current is not null ? throw new AgeException($"unexpected argument: {arg}") : arg;
    }

    private static int Generate(string? outputPath, bool postQuantum)
    {
        var (publicKey, secretKey) = GenerateKeyPair(postQuantum);
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var output = $"# created: {timestamp}\n# public key: {publicKey}\n{secretKey}\n";
        return WriteKeyOutput(output, publicKey, outputPath);
    }

    private static (string publicKey, string secretKey) GenerateKeyPair(bool postQuantum)
    {
        if (postQuantum)
        {
            using var identity = AgeKeygen.GeneratePq();
            return (identity.Recipient.ToString(), identity.ToString());
        }

        using var x = AgeKeygen.Generate();
        return (x.Recipient.ToString(), x.ToString());
    }

    private static int WriteKeyOutput(string output, string publicKey, string? outputPath)
    {
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
        var text = inputPath is not null
            ? File.ReadAllText(inputPath)
            : Console.In.ReadToEnd();

        var recipients = text.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(IdentityToPublicKey)
            .ToList();

        if (recipients.Count == 0)
            throw new AgeException("no identity found");

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