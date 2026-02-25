using Age.Recipients;

namespace Age.Cli;

internal static class KeygenCommand
{
    public static int Execute(string? outputPath, bool convertToPublic, bool postQuantum, string? inputPath)
    {
        return convertToPublic
            ? ConvertToPublic(inputPath, outputPath)
            : Generate(outputPath, postQuantum);
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

    private static void Error(string message)
    {
        Console.Error.WriteLine($"age-keygen: {message}");
    }
}