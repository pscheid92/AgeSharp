using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace AgeSharp.TestKit;

public class CctvTestRunner
{
    private static readonly string TestDataDir = Path.Combine(
        AppContext.BaseDirectory, "testdata");

    public static IEnumerable<object[]> GetTestVectors()
    {
        if (!Directory.Exists(TestDataDir))
            yield break;

        foreach (var file in Directory.EnumerateFiles(TestDataDir).OrderBy(f => f))
        {
            var name = Path.GetFileName(file);
            // Vectors are extensionless: a dot means a stray file (.DS_Store, stale
            // pre-rename *.txt copies in the output dir). Also skip unsupported vectors.
            if (name.Contains('.') || name.StartsWith("p256tag_") || name.StartsWith("mlkem768p256tag_"))
                continue;
            yield return new object[] { name, file };
        }
    }

    [Theory]
    [MemberData(nameof(GetTestVectors))]
    public void RunTestVector(string name, string path)
    {
        _ = name; // Used for test display
        var (metadata, identityStrings, ageFileBytes) = ParseTestFile(path);

        var expect = metadata["expect"];
        var passphrase = metadata.GetValueOrDefault("passphrase");
        var payloadHash = metadata.GetValueOrDefault("payload");

        // Build identities
        var identities = new List<IIdentity>();
        foreach (var identityStr in identityStrings)
            if (identityStr.StartsWith("AGE-SECRET-KEY-PQ-", StringComparison.OrdinalIgnoreCase))
                identities.Add(MlKem768X25519Identity.Parse(identityStr));
            else if (identityStr.StartsWith("AGE-SECRET-KEY-1", StringComparison.OrdinalIgnoreCase))
                identities.Add(X25519Identity.Parse(identityStr));
            else if (identityStr.StartsWith("-----BEGIN"))
                identities.Add(Age.ParseIdentity(identityStr));
        if (passphrase != null)
            identities.Add(new Passphrase(passphrase));

        // Some failure vectors ship no identities at all: the file must be rejected
        // while parsing the header, before identity matching. Decrypt requires at
        // least one identity (as the Go reference does), so supply a throwaway one —
        // it can never match, and the expected failure must occur first.
        if (identities.Count == 0)
            identities.Add(X25519Identity.Generate());

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

        Age.Decrypt(input, output, identities.ToArray());

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
            Age.Decrypt(input, output, identities.ToArray()));
    }

    private static void RunHmacFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        Assert.Throws<AgeAuthenticationException>(() =>
            Age.Decrypt(input, output, identities.ToArray()));
    }

    private static void RunHeaderFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        var ex = Assert.ThrowsAny<AgeException>(() =>
            Age.Decrypt(input, output, identities.ToArray()));
        Assert.True(ex is AgeFormatException or AgeAuthenticationException,
            $"Expected AgeFormatException or AgeAuthenticationException, got {ex.GetType().Name}: {ex.Message}");
    }

    private static void RunPayloadFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        Assert.Throws<AgeAuthenticationException>(() =>
            Age.Decrypt(input, output, identities.ToArray()));
    }

    // Armor defects are structural by definition — a single exact type now.
    private static void RunArmorFailureTest(byte[] ageFileBytes, List<IIdentity> identities)
    {
        using var input = new MemoryStream(ageFileBytes);
        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() =>
            Age.Decrypt(input, output, identities.ToArray()));
    }

    private static (Dictionary<string, string> metadata, List<string> identityStrings, byte[] ageFileBytes)
        ParseTestFile(string path)
    {
        // The file consists of:
        // 1. Header lines (key: value pairs)
        // 2. A blank line
        // 3. The raw age file bytes (binary), possibly zlib-compressed
        var allBytes = File.ReadAllBytes(path);

        var metadata = new Dictionary<string, string>();
        var identityStrings = new List<string>();
        var pos = 0;

        while (pos < allBytes.Length)
        {
            var lineEnd = Array.IndexOf(allBytes, (byte)'\n', pos);
            if (lineEnd < 0) break;

            if (lineEnd == pos)
            {
                pos = lineEnd + 1;
                break;
            }

            var line = Encoding.UTF8.GetString(allBytes, pos, lineEnd - pos);
            pos = lineEnd + 1;

            var colonIdx = line.IndexOf(": ");
            if (colonIdx >= 0)
            {
                var key = line[..colonIdx];
                var value = line[(colonIdx + 2)..];
                if (key == "identity")
                    identityStrings.Add(value);
                metadata[key] = value;
            }
        }

        var bodyBytes = new byte[allBytes.Length - pos];
        Array.Copy(allBytes, pos, bodyBytes, 0, bodyBytes.Length);

        // Handle zlib compression
        if (metadata.TryGetValue("compressed", out var compression) && compression == "zlib")
            bodyBytes = ZlibDecompress(bodyBytes);

        return (metadata, identityStrings, bodyBytes);
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