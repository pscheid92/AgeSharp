using System.Text;
using AgeSharp;
using AgeSharp.Crypto;
using Xunit;
using Xunit.Abstractions;

namespace Age.Tests;

/// <summary>
/// Whatever is done to a file, reading it fails with an <see cref="AgeException"/> or not at all:
/// no raw exception (an index out of range, a cryptography error, an argument check) escapes,
/// on any way of reading. Strings that are not keys fail to parse with <see cref="FormatException"/>.
/// </summary>
/// <remarks>
/// The damage is deterministic (a fixed seed), so a failure here reproduces. Each fact collects
/// every offence before failing, so one run shows them all.
/// </remarks>
public class HostileInputTests(ITestOutputHelper output)
{
    private static readonly byte[] Plaintext = Enumerable.Range(0, 2 * StreamEncryption.ChunkSize + 300).Select(i => (byte)(i * 17)).ToArray();

    public static TheoryData<string> Files => ["binary", "armored", "postquantum", "two recipients"];

    [Theory]
    [MemberData(nameof(Files))]
    public async Task DamagedFiles_FailOnlyAsAgeExceptions(string kind)
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        using var carol = MlKem768X25519Identity.Generate();

        var file = kind switch
        {
            "binary" => new Recipients(alice.Recipient).Encrypt(Plaintext),
            "armored" => new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }),
            "postquantum" => new Recipients(carol.Recipient).Encrypt(Plaintext),
            _ => new Recipients(alice.Recipient, bob.Recipient).Encrypt(Plaintext),
        };

        var with = new Identities(alice, carol);
        var offences = new List<string>();

        foreach (var (damage, damaged) in Damaged(file))
        {
            foreach (var (way, read) in Ways(with))
            {
                var escaped = await Escaped(() => read(damaged));

                if (escaped is not null)
                    offences.Add($"{damage} via {way}: {escaped.GetType().Name}: {escaped.Message}");
            }
        }

        foreach (var offence in offences.Take(40))
            output.WriteLine(offence);

        Assert.True(offences.Count == 0, $"{offences.Count} raw exceptions escaped; first: {offences.FirstOrDefault()}");
    }

    [Fact]
    public void StringsThatAreNotKeys_FailToParseAsFormatExceptions()
    {
        var offences = new List<string>();

        foreach (var text in NotKeys())
        {
            foreach (var (what, parse) in new (string, Func<string, object>)[]
                     {
                         ("Recipients.ParseOne", s => Recipients.ParseOne(s)),
                         ("Identities.ParseOne", s => Identities.ParseOne(s)),
                         ("Recipients.Parse", s => Recipients.Parse(s)),
                         ("Identities.Parse", s => Identities.Parse(s)),
                         ("SshIdentity.Parse", s => SshIdentity.Parse(s)),
                         ("SshIdentity.Parse with a passphrase", s => SshIdentity.Parse(s, () => "pw".ToCharArray())),
                     })
            {
                try
                {
                    (parse(text) as IDisposable)?.Dispose();
                }
                catch (FormatException)
                {
                }
                catch (Exception ex)
                {
                    offences.Add($"{what}({Shown(text)}): {ex.GetType().Name}: {ex.Message}");
                }
            }
        }

        foreach (var offence in offences.Take(40))
            output.WriteLine(offence);

        Assert.True(offences.Count == 0, $"{offences.Count} parses failed with something else; first: {offences.FirstOrDefault()}");
    }

    // Every way a file can be read, each driven to its end.
    private static IEnumerable<(string, Func<byte[], Task>)> Ways(Identities with) =>
    [
        ("Decrypt", f => { with.Decrypt(f); return Task.CompletedTask; }),
        ("Decrypt from a pipe", f => { with.Decrypt(new NonSeekableStream(new MemoryStream(f)), Stream.Null); return Task.CompletedTask; }),
        ("DecryptAsync from a pipe", f => with.DecryptAsync(new NonSeekableStream(new MemoryStream(f)), Stream.Null)),
        ("the seekable reader", f =>
        {
            using var reader = with.DecryptReader(new MemoryStream(f));
            reader.CopyTo(Stream.Null);

            if (reader.CanSeek && reader.Length > 10)
            {
                reader.Position = reader.Length / 2;
                reader.ReadAtLeast(new byte[100], 1, throwOnEndOfStream: false);
            }

            return Task.CompletedTask;
        }),
        ("the async seekable reader", async f =>
        {
            await using var reader = await with.DecryptReaderAsync(new MemoryStream(f));
            await reader.CopyToAsync(Stream.Null);
        }),
        ("the writer", f =>
        {
            using (var writer = with.DecryptWriter(Stream.Null))
            {
                for (var at = 0; at < f.Length; at += 997)
                    writer.Write(f, at, Math.Min(997, f.Length - at));
            }

            return Task.CompletedTask;
        }),
        ("the async writer", async f =>
        {
            await using var writer = with.DecryptWriter(Stream.Null);
            await writer.WriteAsync(f);
        }),
        ("DecryptDetached", f =>
        {
            with.DecryptDetached(new MemoryStream(f), new MemoryStream(f), Stream.Null);
            return Task.CompletedTask;
        }),
        ("AgeHeader.Read", f => { AgeHeader.Read(new MemoryStream(f)); return Task.CompletedTask; }),
        ("AgeHeader.ReadAsync", async f => await AgeHeader.ReadAsync(new NonSeekableStream(new MemoryStream(f)))),
        ("Armor.Decode", f =>
        {
            if (f.AsSpan().TrimStart(" \t\r\n"u8).StartsWith("-----BEGIN"u8))
                Armor.Decode(new MemoryStream(f), Stream.Null);
            return Task.CompletedTask;
        }),
    ];

    private static async Task<Exception?> Escaped(Func<Task> read)
    {
        try
        {
            await read();
            return null;
        }
        catch (AgeException)
        {
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    // Truncations, flipped bits, inserted and replaced bytes: thick in the header, where parsing
    // happens, and spread over the payload.
    private static IEnumerable<(string, byte[])> Damaged(byte[] file)
    {
        var random = new Random(20261121);
        var headerEnd = Math.Min(file.Length, 1600);

        foreach (var at in Positions(file.Length, headerEnd, random))
        {
            yield return ($"cut at {at}", file[..at]);

            var flipped = file.ToArray();
            flipped[at] ^= (byte)(1 << random.Next(8));
            yield return ($"bit flipped at {at}", flipped);

            yield return ($"byte inserted at {at}", [.. file[..at], (byte)random.Next(256), .. file[at..]]);
        }

        // A header line's bytes replaced with ASCII, controls and non-ASCII alike.
        for (var i = 0; i < 200; i++)
        {
            var garbled = file.ToArray();
            var at = random.Next(headerEnd);
            var length = random.Next(1, 40);

            for (var j = at; j < Math.Min(garbled.Length, at + length); j++)
                garbled[j] = (byte)random.Next(256);

            yield return ($"garbled {length} bytes at {at}", garbled);
        }

        yield return ("empty", []);
        yield return ("doubled", [.. file, .. file]);
    }

    private static IEnumerable<int> Positions(int length, int headerEnd, Random random)
    {
        for (var at = 0; at < headerEnd && at < length; at += 7)
            yield return at;

        for (var i = 0; i < 60; i++)
            yield return random.Next(headerEnd, length);
    }

    private static IEnumerable<string> NotKeys()
    {
        var random = new Random(4242);

        string[] fixedOnes =
        [
            "", " ", "\n", "age1", "age1pq1", "age1tag1", "age1tagpq1", "age1x1", "AGE-SECRET-KEY-1", "AGE-SECRET-KEY-PQ-1",
            "AGE-PLUGIN-X-1", "AGE-PLUGIN--1QQQ", "ssh-ed25519", "ssh-ed25519 ", "ssh-ed25519 AAAA", "ssh-rsa AAAAB3NzaC1yc2E=",
            "ssh-rsa !!!", "-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "-----BEGIN", "\0\0\0", "age1éé",
        ];

        foreach (var text in fixedOnes)
            yield return text;

        // Real keys, damaged.
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        string[] real = [x25519.ToSecretString(), x25519.Recipient.ToString(), pq.ToSecretString(), pq.Recipient.ToString(), SshKeys.Ed25519Pem()];

        foreach (var key in real)
        {
            for (var i = 0; i < 40; i++)
            {
                var chars = key.ToCharArray();
                var at = random.Next(chars.Length);
                chars[at] = (char)random.Next(32, 0x2FF);
                yield return new string(chars);
                yield return key[..random.Next(key.Length)];
            }
        }
    }

    private static string Shown(string text) =>
        text.Length > 40 ? text[..40].ReplaceLineEndings("\\n") + "…" : text.ReplaceLineEndings("\\n");
}
