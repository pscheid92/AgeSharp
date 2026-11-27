using System.Security.Cryptography;
using AgeSharp;

namespace Age.Fuzz;

/// <summary>
/// Decrypts each input four ways — Decrypt, DecryptReader over a seekable stream and over a
/// pipe, DecryptWriter — which must agree: all succeed with the same plaintext, or all fail
/// with an AgeException of the same type. The pipe and the writer take the input in sizes drawn
/// from it, so chunk and line boundaries fall everywhere.
/// </summary>
/// <remarks>
/// The identities are the test vectors' (X25519, ML-KEM-768-X25519, the passphrase), and the
/// unprotected SSH Ed25519 and RSA test keys, so every native stanza type reaches an identity
/// that tries it. The seeds are the vectors' files and files encrypted to each identity.
/// </remarks>
internal static class DecryptTarget
{
    public static Target Create(string repo)
    {
        var identities = new List<IIdentity>();
        foreach (var key in Seeds.Vectors(repo).SelectMany(v => v.Identities).Distinct())
            identities.Add(key.StartsWith("AGE-SECRET-KEY-PQ-", StringComparison.Ordinal) ? MlKem768X25519Identity.Parse(key) : X25519Identity.Parse(key));
        // The vectors' passphrase; scrypt is most of this target's time, so only the one.
        identities.Add(new Passphrase("password") { MaxWorkFactor = 12 });
        foreach (var key in new[] { "ed25519_plain", "rsa_plain" })
            identities.Add(SshIdentity.Parse(File.ReadAllText(Path.Combine(Seeds.SshKeyDir(repo), key))));

        var all = new Identities(identities);
        return new Target(data => Decrypt(all, data), () => Seeds.Files(repo).Concat(Encrypted(identities)));
    }

    // A few files to each identity with a recipient: empty, one byte, and either side of a
    // chunk boundary (RSA only the one byte: it is slow, and every mutant of its files tries it).
    private static IEnumerable<byte[]> Encrypted(List<IIdentity> identities)
    {
        foreach (var identity in identities.OfType<IIdentityWithRecipient>())
        {
            int[] sizes = identity is SshRsaIdentity ? [1] : [0, 1, 65536, 65537];
            foreach (var size in sizes)
                yield return new Recipients(identity.Recipient).Encrypt(RandomNumberGenerator.GetBytes(size));
            yield return new Recipients(identity.Recipient).Encrypt("armored"u8, new AgeEncryptOptions { Armor = true });
        }
    }

    private static string Decrypt(Identities identities, byte[] data)
    {
        var sizes = new Random(BitConverter.ToInt32(SHA256.HashData(data)));
        var readSize = sizes.Next(1, 70_000);

        (byte[]? Plaintext, AgeException? Failure)[] all =
        [
            Outcome(() => identities.Decrypt(data)),
            Outcome(() => Drain(identities.DecryptReader(new MemoryStream(data)))),
            Outcome(() => Drain(identities.DecryptReader(new Pipe(data, readSize)))),
            Outcome(() =>
            {
                using var output = new MemoryStream();
                using (var writer = identities.DecryptWriter(output))
                {
                    for (var at = 0; at < data.Length;)
                    {
                        var n = Math.Min(data.Length - at, sizes.Next(1, 70_000));
                        writer.Write(data, at, n);
                        at += n;
                    }
                }
                return output.ToArray();
            }),
        ];

        var pattern = string.Join(" ", all.Select(o => o.Plaintext is not null ? "ok" : o.Failure!.GetType().Name));
        string[] paths = ["Decrypt", "seekable DecryptReader", "piped DecryptReader", "DecryptWriter"];
        var detail = string.Join("\n", all.Select((o, i) => $"{paths[i]}: " + (o.Plaintext is not null ? $"{o.Plaintext.Length} bytes" : $"{o.Failure!.GetType().Name}: {o.Failure.Message}")));

        if (all.Any(o => !SameResult(all[0], o)))
            throw new Finding($"the decrypt paths disagree: {pattern}", detail);
        if (all.Select(o => o.Failure?.GetType()).Distinct().Count() > 1)
            throw new Finding($"the decrypt paths fail differently: {pattern}", detail);

        return all[0].Plaintext is not null ? "ok" : Outcomes.Shape(all[0].Failure!);
    }

    private static (byte[]? Plaintext, AgeException? Failure) Outcome(Func<byte[]> decrypt)
    {
        try
        {
            return (decrypt(), null);
        }
        catch (AgeException ex)
        {
            return (null, ex);
        }
    }

    private static bool SameResult((byte[]? Plaintext, AgeException? Failure) a, (byte[]? Plaintext, AgeException? Failure) b) =>
        a.Plaintext is not null && b.Plaintext is not null
            ? a.Plaintext.AsSpan().SequenceEqual(b.Plaintext)
            : a.Plaintext is null && b.Plaintext is null;

    private static byte[] Drain(Stream reader)
    {
        using var output = new MemoryStream();
        using (reader)
            reader.CopyTo(output);
        return output.ToArray();
    }
}
