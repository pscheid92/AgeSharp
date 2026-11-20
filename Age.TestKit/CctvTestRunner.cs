using AgeSharp;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using OuterLoop;
using Xunit;
using static OuterLoop.AgeUnderTest;

namespace Age.TestKit;

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
            // Every vector three times: from a seekable stream; from a pipe, which armor
            // detection must handle by reading ahead rather than seeking; and from a pipe
            // asynchronously, where every read and write is awaited.
            yield return new object[] { name, file, false, false };
            yield return new object[] { name, file, true, false };
            yield return new object[] { name, file, true, true };
        }
    }

    [Theory]
    [MemberData(nameof(GetTestVectors))]
    public void RunTestVector(string name, string path, bool overAPipe, bool asynchronously)
    {
        _ = name; // Used for test display
        var (metadata, identityStrings, ageFileBytes) = ParseTestFile(path);

        string expect = metadata["expect"];
        string? passphrase = metadata.GetValueOrDefault("passphrase");
        string? payloadHash = metadata.GetValueOrDefault("payload");

        var decryption = AgeUnderTest.TryDecrypt(ageFileBytes, identityStrings, passphrase, overAPipe, asynchronously);

        Assert.True(Accepted(expect).Contains(decryption.Outcome),
            $"expected {expect}, got {decryption.Outcome}: {decryption.Error}");

        if (decryption.Outcome == Outcome.Success)
        {
            Assert.NotNull(payloadHash);
            Assert.Equal(payloadHash, Convert.ToHexStringLower(SHA256.HashData(decryption.Plaintext!)));
        }
    }

    public static IEnumerable<object[]> GetVectorFiles() =>
        GetTestVectors().Where(v => !(bool)v[2]).Select(v => new[] { v[0], v[1] });

    // Not just the same category: the three ways of reading a file end identically, the error
    // message included, so no path reports a failure differently from the others.
    [Theory]
    [MemberData(nameof(GetVectorFiles))]
    public void EveryWayOfReading_EndsTheSame(string name, string path)
    {
        _ = name;
        var (metadata, identityStrings, ageFileBytes) = ParseTestFile(path);
        var passphrase = metadata.GetValueOrDefault("passphrase");

        var fromFile = AgeUnderTest.TryDecrypt(ageFileBytes, identityStrings, passphrase);
        var fromPipe = AgeUnderTest.TryDecrypt(ageFileBytes, identityStrings, passphrase, overAPipe: true);
        var asynchronously = AgeUnderTest.TryDecrypt(ageFileBytes, identityStrings, passphrase, overAPipe: true, asynchronously: true);

        foreach (var other in new[] { fromPipe, asynchronously })
        {
            Assert.Equal(fromFile.Outcome, other.Outcome);
            Assert.Equal(fromFile.Error, other.Error);
            Assert.Equal(fromFile.Plaintext, other.Plaintext);
        }
    }

    // What each expectation accepts. A header failure may also surface as a MAC failure, and an
    // armor failure as a header failure: the vectors say which stage breaks, and AgeSharp's
    // parsers sometimes notice one stage later.
    private static Outcome[] Accepted(string expect) => expect switch
    {
        "success" => [Outcome.Success],
        "no match" => [Outcome.NoMatch],
        "HMAC failure" => [Outcome.MacFailure],
        "header failure" => [Outcome.HeaderFailure, Outcome.MacFailure],
        "payload failure" => [Outcome.PayloadFailure],
        "armor failure" => [Outcome.ArmorFailure, Outcome.HeaderFailure],
        _ => throw new InvalidOperationException($"unknown expect value: {expect}"),
    };

    private static (Dictionary<string, string> metadata, List<string> identityStrings, byte[] ageFileBytes) ParseTestFile(string path)
    {
        // The file consists of:
        // 1. Header lines (key: value pairs)
        // 2. A blank line
        // 3. The raw age file bytes (binary), possibly zlib-compressed
        var allBytes = File.ReadAllBytes(path);

        var metadata = new Dictionary<string, string>();
        var identityStrings = new List<string>();
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
                if (key == "identity")
                    identityStrings.Add(value);
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
