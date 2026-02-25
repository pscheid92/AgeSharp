using Age;
using Age.Format;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Age.Cli;

internal record InspectOutput(string File, string Version, bool Armored, bool PostQuantum, InspectRecipient[] Recipients, InspectSize Size);
internal record InspectRecipient(int Index, string Type, string[] Args);
internal record InspectSize(long Header, long Overhead, long Payload, long Total);

[JsonSerializable(typeof(InspectOutput))]
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class InspectJsonContext : JsonSerializerContext;

internal static class InspectCommand
{
    public static int Run(string[] args)
    {
        try
        {
            return Execute(args);
        }
        catch (AgeException ex)
        {
            Error(ex.Message);
            return 1;
        }
        catch (FileNotFoundException ex)
        {
            Error($"no such file: {ex.FileName}");
            return 1;
        }
    }

    private record InspectArgs(string? FilePath, bool Json);

    private static int Execute(string[] args)
    {
        var parsed = ParseArgs(args);
        if (parsed is null)
            return 0;

        var (rawInput, displayName) = parsed.FilePath is not null
            ? ((Stream)File.OpenRead(parsed.FilePath), parsed.FilePath)
            : (Console.OpenStandardInput(), "(stdin)");

        using (rawInput)
        {
            var ms = new MemoryStream();
            rawInput.CopyTo(ms);
            var totalSize = ms.Length;
            ms.Position = 0;

            var header = AgeHeader.Parse(ms);

            if (parsed.Json)
                PrintJson(header, displayName, totalSize);
            else
                PrintHuman(header, displayName, totalSize);
        }

        return 0;
    }

    private static InspectArgs? ParseArgs(string[] args)
    {
        string? filePath = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return null;
                case "--json":
                    json = true;
                    break;
                case "-":
                    filePath = null;
                    break;
                default:
                    filePath = ParsePositionalArg(args[i], filePath);
                    break;
            }
        }

        return new InspectArgs(filePath, json);
    }

    private static string ParsePositionalArg(string arg, string? current)
    {
        if (arg.StartsWith('-'))
            throw new AgeException($"unknown option: {arg}");

        return current is not null ? throw new AgeException("too many arguments") : arg;
    }

    private const int PayloadNonceSize = 16;
    private const int ChunkSize = 64 * 1024;
    private const int TagSize = 16;
    private const int EncryptedChunkSize = ChunkSize + TagSize;

    private static readonly HashSet<string> PostQuantumTypes = ["mlkem768x25519"];

    private static void PrintHuman(AgeHeader header, string displayName, long totalSize)
    {
        Console.WriteLine($"{displayName} is an age file, version \"age-encryption.org/v1\".");
        Console.WriteLine();

        var types = header.Recipients.Select(s => s.Type).Distinct().ToList();
        Console.WriteLine("This file is encrypted to the following recipient types:");
        foreach (var type in types)
            Console.WriteLine($"  - \"{type}\"");
        Console.WriteLine();

        var hasPq = types.Any(t => PostQuantumTypes.Contains(t));
        Console.WriteLine(hasPq
            ? "This file uses post-quantum encryption."
            : "This file does NOT use post-quantum encryption.");
        Console.WriteLine();

        var sizes = ComputeSizes(header, totalSize);
        Console.WriteLine("Size breakdown (assuming it decrypts successfully):");
        Console.WriteLine();
        Console.WriteLine($"    {"Header",-24}{sizes.Header,8} bytes");
        Console.WriteLine($"    {"Encryption overhead",-24}{sizes.Overhead,8} bytes");
        Console.WriteLine($"    {"Payload",-24}{sizes.Payload,8} bytes");
        Console.WriteLine($"    {"",24}-------------------");
        Console.WriteLine($"    {"Total",-24}{sizes.Total,8} bytes");
        Console.WriteLine();

        Console.WriteLine("Tip: for machine-readable output, use --json.");
    }

    private static void PrintJson(AgeHeader header, string displayName, long totalSize)
    {
        var sizes = ComputeSizes(header, totalSize);

        var obj = new InspectOutput(
            File: displayName,
            Version: "age-encryption.org/v1",
            Armored: header.IsArmored,
            PostQuantum: header.Recipients.Any(s => PostQuantumTypes.Contains(s.Type)),
            Recipients: header.Recipients.Select((s, i) => new InspectRecipient(i, s.Type, s.Args)).ToArray(),
            Size: new InspectSize(sizes.Header, sizes.Overhead, sizes.Payload, sizes.Total)
        );

        Console.WriteLine(JsonSerializer.Serialize(obj, InspectJsonContext.Default.InspectOutput));
    }

    private record SizeBreakdown(long Header, long Overhead, long Payload, long Total);

    private static SizeBreakdown ComputeSizes(AgeHeader header, long totalSize)
    {
        var headerSize = header.PayloadOffset;
        var encryptedPayload = totalSize - headerSize;
        var overhead = ComputeOverhead(encryptedPayload);
        var payload = encryptedPayload - overhead;
        return new SizeBreakdown(headerSize, overhead, payload, totalSize);
    }

    private static long ComputeOverhead(long encryptedPayload)
    {
        if (encryptedPayload <= PayloadNonceSize)
            return encryptedPayload;

        var afterNonce = encryptedPayload - PayloadNonceSize;
        var fullChunks = afterNonce / EncryptedChunkSize;
        var remainder = afterNonce % EncryptedChunkSize;
        var totalChunks = fullChunks + (remainder > 0 ? 1 : 0);
        return PayloadNonceSize + totalChunks * TagSize;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("""
            Usage:
                age-inspect [--json] [INPUT]

            Options:
                --json                      Output machine-readable JSON.

            INPUT defaults to standard input. "-" may be used as INPUT to explicitly
            read from standard input.
            """);
    }

    private static void Error(string msg) =>
        Console.Error.WriteLine($"age-inspect: {msg}");
}
