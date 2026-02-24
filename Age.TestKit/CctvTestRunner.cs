using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Age;
using Age.Recipients;
using Xunit;

namespace Age.TestKit;

public class CctvTestRunner
{
    private static readonly string TestDataDir = Path.Combine(
        AppContext.BaseDirectory, "testdata");

    public static IEnumerable<object[]> GetTestVectors()
    {
        if (!Directory.Exists(TestDataDir))
            yield break;

        foreach (var file in Directory.EnumerateFiles(TestDataDir, "*.txt").OrderBy(f => f))
        {
            var name = Path.GetFileNameWithoutExtension(file);
            // Skip unsupported test vectors (hybrid/PQ identities)
            if (name.StartsWith("hybrid_") || name.StartsWith("p256tag_") || name.StartsWith("mlkem768p256tag_")
                || name == "hybrid" || name == "armor_hybrid")
                continue;
            yield return new object[] { name, file };
        }
    }

    [Theory]
    [MemberData(nameof(GetTestVectors))]
    public void RunTestVector(string name, string path)
    {
        _ = name; // Used for test display
        var (metadata, ageFileBytes) = ParseTestFile(path);

        string expect = metadata["expect"];
        string? identityStr = metadata.GetValueOrDefault("identity");
        string? passphrase = metadata.GetValueOrDefault("passphrase");
        string? payloadHash = metadata.GetValueOrDefault("payload");

        // Build identities
        var identities = new List<IIdentity>();
        if (identityStr != null)
        {
            // Only parse X25519 identities; skip unknown types (e.g. PQ)
            if (identityStr.StartsWith("AGE-SECRET-KEY-1"))
                identities.Add(X25519Identity.Parse(identityStr));
        }
        if (passphrase != null)
            identities.Add(new ScryptRecipient(passphrase));

        switch (expect)
        {
            case "success":
                Assert.NotNull(payloadHash);
                RunSuccessTest(ageFileBytes, identities, payloadHash!);
                break;
            case "no match":
                RunNoMatchTest(ageFileBytes, identities);
                break;
            case "HMAC failure":
                RunHmacFailureTest(ageFileBytes, identities);
                break;
            case "header failure":
                RunHeaderFailureTest(ageFileBytes, identities);
                break;
            case "payload failure":
                RunPayloadFailureTest(ageFileBytes, identities);
                break;
            case "armor failure":
                RunArmorFailureTest(ageFileBytes, identities);
                break;
            default:
                Assert.Fail($"unknown expect value: {expect}");
                break;
        }
    }

    private static void RunSuccessTest(byte[] ageFileBytes, List<IIdentity> identities, string expectedPayloadHash)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        AgeEncrypt.Decrypt(input, output, identities.ToArray());

        var plaintext = output.ToArray();
        var hash = SHA256.HashData(plaintext);
        var hashHex = Convert.ToHexStringLower(hash);
        Assert.Equal(expectedPayloadHash, hashHex);
    }

    private static void RunNoMatchTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        Assert.Throws<NoIdentityMatchException>(() =>
            AgeEncrypt.Decrypt(input, output, identities.ToArray()));
    }

    private static void RunHmacFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        Assert.Throws<AgeHmacException>(() =>
            AgeEncrypt.Decrypt(input, output, identities.ToArray()));
    }

    private static void RunHeaderFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        var ex = Assert.ThrowsAny<AgeException>(() =>
            AgeEncrypt.Decrypt(input, output, identities.ToArray()));
        Assert.True(ex is AgeHeaderException or AgeHmacException,
            $"Expected AgeHeaderException or AgeHmacException, got {ex.GetType().Name}: {ex.Message}");
    }

    private static void RunPayloadFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        Assert.Throws<AgePayloadException>(() =>
            AgeEncrypt.Decrypt(input, output, identities.ToArray()));
    }

    private static void RunArmorFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        var ex = Assert.ThrowsAny<AgeException>(() =>
            AgeEncrypt.Decrypt(input, output, identities.ToArray()));
        Assert.True(ex is AgeArmorException or AgeHeaderException,
            $"Expected AgeArmorException or AgeHeaderException, got {ex.GetType().Name}: {ex.Message}");
    }

    private static (Dictionary<string, string> metadata, byte[] ageFileBytes) ParseTestFile(string path)
    {
        // The file consists of:
        // 1. Header lines (key: value pairs)
        // 2. A blank line
        // 3. The raw age file bytes (binary), possibly zlib-compressed
        var allBytes = File.ReadAllBytes(path);

        var metadata = new Dictionary<string, string>();
        int pos = 0;

        while (pos < allBytes.Length)
        {
            int lineEnd = Array.IndexOf(allBytes, (byte)'\n', pos);
            if (lineEnd < 0) break;

            if (lineEnd == pos)
            {
                pos = lineEnd + 1;
                break;
            }

            var line = Encoding.UTF8.GetString(allBytes, pos, lineEnd - pos);
            pos = lineEnd + 1;

            int colonIdx = line.IndexOf(": ");
            if (colonIdx >= 0)
            {
                string key = line[..colonIdx];
                string value = line[(colonIdx + 2)..];
                metadata[key] = value;
            }
        }

        var bodyBytes = new byte[allBytes.Length - pos];
        Array.Copy(allBytes, pos, bodyBytes, 0, bodyBytes.Length);

        // Handle zlib compression
        if (metadata.TryGetValue("compressed", out var compression) && compression == "zlib")
        {
            bodyBytes = ZlibDecompress(bodyBytes);
        }

        return (metadata, bodyBytes);
    }

    private static byte[] ZlibDecompress(byte[] data)
    {
        // zlib format: 2-byte header + deflate data + 4-byte checksum
        // ZLibStream handles this
        using var input = new MemoryStream(data);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }
}
