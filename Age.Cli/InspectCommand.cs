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
        string? filePath = null;
        var json = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return 0;
                case "--json":
                    json = true;
                    break;
                case "-":
                    filePath = null;
                    break;
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
                // Buffer into a seekable stream so we can measure total size
                var ms = new MemoryStream();
                rawInput.CopyTo(ms);
                long totalSize = ms.Length;
                ms.Position = 0;

                var header = AgeHeader.Parse(ms);

                if (json)
                    PrintJson(header, displayName, totalSize);
                else
                    PrintHuman(header, displayName, totalSize);
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

    private const int PayloadNonceSize = 16;
    private const int ChunkSize = 64 * 1024;
    private const int TagSize = 16;
    private const int EncryptedChunkSize = ChunkSize + TagSize;

    private static readonly HashSet<string> PostQuantumTypes = ["mlkem768x25519"];

    private static void PrintHuman(AgeHeader header, string displayName, long totalSize)
    {
        Console.WriteLine($"{displayName} is an age file, version \"age-encryption.org/v1\".");
        Console.WriteLine();

        // Recipient types (deduplicated, preserving order)
        var types = header.Recipients.Select(s => s.Type).Distinct().ToList();
        Console.WriteLine("This file is encrypted to the following recipient types:");
        foreach (var type in types)
            Console.WriteLine($"  - \"{type}\"");
        Console.WriteLine();

        // Post-quantum check
        bool hasPq = types.Any(t => PostQuantumTypes.Contains(t));
        if (hasPq)
            Console.WriteLine("This file uses post-quantum encryption.");
        else
            Console.WriteLine("This file does NOT use post-quantum encryption.");
        Console.WriteLine();

        // Size breakdown
        long headerSize = header.PayloadOffset;
        long encryptedPayload = totalSize - headerSize;
        long overhead = ComputeOverhead(encryptedPayload);
        long payload = encryptedPayload - overhead;

        Console.WriteLine("Size breakdown (assuming it decrypts successfully):");
        Console.WriteLine();
        Console.WriteLine($"    {"Header",-24}{headerSize,8} bytes");
        Console.WriteLine($"    {"Encryption overhead",-24}{overhead,8} bytes");
        Console.WriteLine($"    {"Payload",-24}{payload,8} bytes");
        Console.WriteLine($"    {"",24}-------------------");
        Console.WriteLine($"    {"Total",-24}{totalSize,8} bytes");
        Console.WriteLine();

        Console.WriteLine("Tip: for machine-readable output, use --json.");
    }

    private static long ComputeOverhead(long encryptedPayload)
    {
        if (encryptedPayload <= PayloadNonceSize)
            return encryptedPayload;

        long afterNonce = encryptedPayload - PayloadNonceSize;
        long fullChunks = afterNonce / EncryptedChunkSize;
        long remainder = afterNonce % EncryptedChunkSize;
        long totalChunks = fullChunks + (remainder > 0 ? 1 : 0);
        return PayloadNonceSize + totalChunks * TagSize;
    }

    private static void PrintJson(AgeHeader header, string displayName, long totalSize)
    {
        long headerSize = header.PayloadOffset;
        long encryptedPayload = totalSize - headerSize;
        long overhead = ComputeOverhead(encryptedPayload);
        long payload = encryptedPayload - overhead;

        var obj = new InspectOutput(
            File: displayName,
            Version: "age-encryption.org/v1",
            Armored: header.IsArmored,
            PostQuantum: header.Recipients.Any(s => PostQuantumTypes.Contains(s.Type)),
            Recipients: header.Recipients.Select((s, i) => new InspectRecipient(i, s.Type, s.Args)).ToArray(),
            Size: new InspectSize(headerSize, overhead, payload, totalSize)
        );

        Console.WriteLine(JsonSerializer.Serialize(obj, InspectJsonContext.Default.InspectOutput));
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

    private static void Error(string msg)
    {
        Console.Error.WriteLine($"age-inspect: {msg}");
    }
}
