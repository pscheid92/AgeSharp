using System.IO.Compression;
using System.Text;
using AgeSharp;

namespace Age.Fuzz;

/// <summary>Finds the repository the fuzzer runs from, for its test data.</summary>
internal static class Repo
{
    // Above the program, or else above the working directory (for a copy built elsewhere).
    public static string Root()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
        {
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
            {
                if (File.Exists(Path.Combine(dir.FullName, "AgeSharp.slnx")))
                    return dir.FullName;
            }
        }
        throw new InvalidOperationException("Age.Fuzz runs from within the AgeSharp repository: AgeSharp.slnx was not found above " + AppContext.BaseDirectory + " or the working directory");
    }
}

/// <summary>
/// The seeds: the repository's own test data (the C2SP test vectors, the SSH test keys), what
/// can be generated from it, and Age.Fuzz/corpus/&lt;target&gt; — inputs kept by hand, such as
/// ones that once found a bug.
/// </summary>
internal static class Seeds
{
    public sealed record Vector(string Name, List<string> Identities, bool Armored, byte[] File);

    /// <summary>The C2SP test vectors in Age.TestKit/testdata, read as CctvTestRunner reads them.</summary>
    public static IEnumerable<Vector> Vectors(string repo)
    {
        foreach (var path in Directory.GetFiles(Path.Combine(repo, "Age.TestKit", "testdata")).Order())
        {
            var bytes = File.ReadAllBytes(path);
            var identities = new List<string>();
            var metadata = new Dictionary<string, string>();
            var pos = 0;
            while (pos < bytes.Length)
            {
                var end = Array.IndexOf(bytes, (byte)'\n', pos);
                if (end < 0)
                    break;
                if (end == pos)
                {
                    pos++;
                    break;
                }
                var line = Encoding.UTF8.GetString(bytes, pos, end - pos);
                pos = end + 1;
                var colon = line.IndexOf(": ", StringComparison.Ordinal);
                if (colon < 0)
                    continue;
                if (line[..colon] == "identity")
                    identities.Add(line[(colon + 2)..]);
                metadata[line[..colon]] = line[(colon + 2)..];
            }

            var body = bytes[pos..];
            if (metadata.GetValueOrDefault("compressed") == "zlib")
            {
                using var zlib = new ZLibStream(new MemoryStream(body), CompressionMode.Decompress);
                using var output = new MemoryStream();
                zlib.CopyTo(output);
                body = output.ToArray();
            }
            yield return new Vector(Path.GetFileName(path), identities, metadata.GetValueOrDefault("armored") == "yes", body);
        }
    }

    public static IEnumerable<byte[]> Files(string repo) =>
        Vectors(repo).Select(v => v.File).Concat(Kept(repo, "decrypt"));

    public static IEnumerable<byte[]> ArmoredFiles(string repo) =>
        Vectors(repo).Where(v => v.Armored).Select(v => v.File).Concat(Kept(repo, "armor"));

    public static IEnumerable<byte[]> IdentityFiles(string repo)
    {
        foreach (var key in Vectors(repo).SelectMany(v => v.Identities).Distinct())
            yield return Encoding.UTF8.GetBytes(key + "\n");
        foreach (var kept in Kept(repo, "identities"))
            yield return kept;
    }

    public static IEnumerable<byte[]> RecipientFiles(string repo)
    {
        foreach (var key in Vectors(repo).SelectMany(v => v.Identities).Distinct())
        {
            using var parsed = Identities.Parse(key);
            yield return Encoding.UTF8.GetBytes(((IIdentityWithRecipient)parsed[0]).Recipient + "\n");
        }
        foreach (var pub in Directory.GetFiles(SshKeyDir(repo), "*.pub"))
            yield return File.ReadAllBytes(pub);
        foreach (var kept in Kept(repo, "recipients"))
            yield return kept;
    }

    public static string SshKeyDir(string repo) => Path.Combine(repo, "Age.Tests", "TestData", "EncryptedSsh");

    /// <summary>The SSH test keys, protected ones with the passphrase hunter2.</summary>
    public static IEnumerable<byte[]> SshKeys(string repo) =>
        Directory.GetFiles(SshKeyDir(repo)).Where(p => !p.EndsWith(".pub", StringComparison.Ordinal)).Order().Select(File.ReadAllBytes).Concat(Kept(repo, "ssh"));

    /// <summary>The SSH test public keys' wire blobs.</summary>
    public static IEnumerable<byte[]> SshPublicBlobs(string repo) =>
        Directory.GetFiles(SshKeyDir(repo), "*.pub").Select(p => Convert.FromBase64String(File.ReadAllText(p).Split(' ')[1])).Concat(Kept(repo, "sshpub"));

    /// <summary>Identity files, encrypted to the passphrase "fuzz" at work factor 10, armored and not.</summary>
    public static IEnumerable<byte[]> EncryptedIdentityFiles(string repo)
    {
        var files = IdentityFiles(repo).ToList();
        files.Add([.. files.SelectMany(f => f)]);
        foreach (var file in files)
        {
            foreach (var armor in new[] { false, true })
            {
                using var passphrase = new Passphrase("fuzz", 10);
                yield return new Recipients(passphrase).Encrypt(file, new AgeEncryptOptions { Armor = armor });
            }
        }
        foreach (var kept in Kept(repo, "identity-file"))
            yield return kept;
    }

    /// <summary>The inputs kept in Age.Fuzz/corpus/<paramref name="target"/>.</summary>
    public static IEnumerable<byte[]> Kept(string repo, string target)
    {
        var dir = Path.Combine(repo, "Age.Fuzz", "corpus", target);
        return Directory.Exists(dir) ? Directory.GetFiles(dir).Order().Select(File.ReadAllBytes) : [];
    }
}
