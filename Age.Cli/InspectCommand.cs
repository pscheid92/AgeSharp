using System.Text.Json;
using System.Text.Json.Serialization;

namespace Age.Cli;

internal record InspectOutput(string File, string Version, bool Armored, bool PostQuantum, InspectRecipient[] Recipients, InspectSize Size);

internal record InspectRecipient(int Index, string Type, string[] Args);

internal record InspectSize(long Header, long Overhead, long Payload, long Total);

internal static class InspectCommand
{
    public static int Execute(string? filePath, bool json)
    {
        var (rawInput, displayName) = filePath is not null
            ? (File.OpenRead(filePath), filePath)
            : (Console.OpenStandardInput(), "(stdin)");

        using (rawInput)
        {
            var ms = new MemoryStream();

            rawInput.CopyTo(ms);
            var totalSize = ms.Length;
            ms.Position = 0;

            var header = AgeHeader.Parse(ms);

            if (json)
                PrintJson(header, displayName, totalSize);
            else
                PrintHuman(header, displayName, totalSize);
        }

        return 0;
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

    private static void Error(string msg) =>
        Console.Error.WriteLine($"age-inspect: {msg}");
}

[JsonSerializable(typeof(InspectOutput))]
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class InspectJsonContext : JsonSerializerContext;