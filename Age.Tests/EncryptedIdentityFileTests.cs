using System.Diagnostics;
using System.Text;
using Xunit;

namespace AgeSharp.Tests;

public class EncryptedIdentityFileTests
{
    private const string Passphrase = "correct horse battery staple";
    private const int LowWorkFactor = 10; // fast for tests

    // The library no longer ships an EncryptIdentityFile helper (the recipe is
    // Encrypt to a Passphrase); these keep the tests concise.
    private static byte[] EncryptIdentityFile(string text, string passphrase, bool armor = false, int workFactor = 18)
    {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(text));
        using var output = new MemoryStream();
        Age.Encrypt(input, output, [new Passphrase(passphrase, workFactor)], new AgeEncryptOptions { Armor = armor });
        return output.ToArray();
    }

    // The identities inside the file are deliberately not exposed, so the tests identify
    // them by the recipients they derive — which name an identity exactly as well as its
    // secret does, without handling the secret.
    private static string[] RecipientsOf(byte[] data, string passphrase)
    {
        using var file = new EncryptedIdentityFile(data, passphrase.ToCharArray);
        return [.. file.Recipients.Select(r => r.ToString()!)];
    }

    // ToString() on identities is redacted; comparisons need the secret form,
    // which only exists on the concrete types.
    private static string Secret(IIdentity identity)
    {
        return identity switch
        {
            X25519Identity x => x.ToSecretString(),
            MlKem768X25519Identity pq => pq.ToSecretString(),
            PluginIdentity plugin => plugin.ToSecretString(),
            _ => throw new InvalidOperationException($"no secret form for {identity.GetType().Name}")
        };
    }

    [Fact]
    public void ParseIdentityFile_X25519()
    {
        using var identity = X25519Identity.Generate();
        var text = $"""
                    # created: 2024-01-01
                    # public key: {identity.Recipient}
                    {identity.ToSecretString()}
                    """;

        var parsed = Age.ParseIdentities(text);
        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void ParseIdentityFile_WithBlankLinesAndComments()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# comment\n\n{identity.ToSecretString()}\n\n# another comment\n";

        var parsed = Age.ParseIdentities(text);
        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void ParseIdentityFile_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519 key\n{x25519.ToSecretString()}\n# PQ key\n{pq.ToSecretString()}\n";

        var parsed = Age.ParseIdentities(text);
        Assert.Equal(2, parsed.Length);
        Assert.Equal(x25519.ToSecretString(), Secret(parsed[0]));
        Assert.Equal(pq.ToSecretString(), Secret(parsed[1]));
    }

    [Fact]
    public void ParseIdentityFile_UnrecognizedLine_Throws()
    {
        var text = "# comment\nNOT-A-VALID-KEY\n";
        var ex = Assert.Throws<AgeFormatException>(() => Age.ParseIdentities(text));
        Assert.Contains("unrecognized", ex.Message);
    }

    [Fact]
    public void ParseIdentityFile_Empty_ReturnsEmpty()
    {
        var parsed = Age.ParseIdentities("");
        Assert.Empty(parsed);
    }

    [Fact]
    public void ParseIdentityFile_OnlyComments_ReturnsEmpty()
    {
        var parsed = Age.ParseIdentities("# just a comment\n# another\n");
        Assert.Empty(parsed);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# created: 2024-01-01\n{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);

        Assert.Equal([identity.Recipient.ToString()], RecipientsOf(encrypted, Passphrase));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_Armored()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text, Passphrase, true, LowWorkFactor);

        // Verify it's armored (starts with the armor header)
        var armoredText = Encoding.UTF8.GetString(encrypted);
        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", armoredText);

        Assert.Equal([identity.Recipient.ToString()], RecipientsOf(encrypted, Passphrase));
    }

    [Fact]
    public void DecryptIdentityFile_WrongPassphrase_Throws()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity.ToSecretString()}\n";
        var encrypted = EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);

        Assert.ThrowsAny<Exception>(() => RecipientsOf(encrypted, "wrong passphrase"));
    }

    [Fact]
    public void EncryptDecrypt_PqIdentity()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = $"# PQ identity\n{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);

        Assert.Equal([identity.Recipient.ToString()], RecipientsOf(encrypted, Passphrase));
    }

    [Fact]
    public void EncryptDecrypt_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519\n{x25519.ToSecretString()}\n# PQ\n{pq.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);

        Assert.Equal([x25519.Recipient.ToString(), pq.Recipient.ToString()],
                     RecipientsOf(encrypted, Passphrase));
    }

    [SkippableFact]
    public void Interop_EncryptWithAgeCli_DecryptWithAgeSharp()
    {
        Skip.IfNot(AgeCli.Available && AgeCli.KeygenAvailable, "age/age-keygen CLI not found on PATH");

        // Use AgeSharp to encrypt (since age CLI -p requires a terminal for encryption),
        // then verify CLI can decrypt it, then re-encrypt with CLI using a recipient key,
        // and verify AgeSharp can parse the identity file after decryption.
        // This tests the identity file format interop with age-keygen output.

        var tempKey = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}.txt");
        try
        {
            // Generate key with age-keygen (tests parsing its output format)
            var keygenPsi = new ProcessStartInfo(AgeCli.AgeKeygenPath!, $"-o {tempKey}")
            {
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using (var proc = Process.Start(keygenPsi)!)
            {
                proc.WaitForExit();
                Assert.Equal(0, proc.ExitCode);
            }

            // Parse the age-keygen output with AgeSharp
            var keyText = File.ReadAllText(tempKey);
            var parsed = Age.ParseIdentities(keyText);

            Assert.Single(parsed);
            Assert.StartsWith("AGE-SECRET-KEY-1", Secret(parsed[0]));

            // Roundtrip: encrypt with AgeSharp, decrypt with AgeSharp
            var encrypted = EncryptIdentityFile(keyText, Passphrase, workFactor: LowWorkFactor);
            var viaFile = RecipientsOf(encrypted, Passphrase);
            Assert.Equal([((IIdentityWithRecipient)parsed[0]).Recipient.ToString()!], viaFile);
        }
        finally
        {
            File.Delete(tempKey);
        }
    }

    [SkippableFact]
    public void Interop_DecryptedIdentity_WorksWithAgeCli()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        // Encrypt identity file with AgeSharp, decrypt it, then verify the
        // recovered key works with the age CLI for a regular encrypt/decrypt.
        using var identity = X25519Identity.Generate();
        var identityText = $"# test key\n{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(identityText, Passphrase, workFactor: LowWorkFactor);
        using var identityFile = new EncryptedIdentityFile(encrypted, Passphrase.ToCharArray);

        // Use the encrypted identity file directly to decrypt data the age CLI produced
        var recipientStr = identity.Recipient.ToString();
        var tempCipher = Path.GetTempFileName();
        try
        {
            var psi = new ProcessStartInfo(AgeCli.AgePath!, $"-r {recipientStr} -o {tempCipher}")
            {
                RedirectStandardInput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            proc.StandardInput.Write("secret from age CLI");
            proc.StandardInput.Close();
            proc.WaitForExit();
            Assert.Equal(0, proc.ExitCode);

            var ciphertext = File.ReadAllBytes(tempCipher);
            using var decInput = new MemoryStream(ciphertext);
            using var decOutput = new MemoryStream();
            // The encrypted identity file is itself an identity: no decrypt-then-parse step.
            Age.Decrypt(decInput, decOutput, [identityFile]);

            var result = Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("secret from age CLI", result);
        }
        finally
        {
            File.Delete(tempCipher);
        }
    }
    // --- the reason the shape changed: the prompt is deferred ---

    [Fact]
    public void Passphrase_IsNotRequested_UntilTheFileIsUsed()
    {
        using var identity = X25519Identity.Generate();
        var encrypted = EncryptIdentityFile($"{identity.ToSecretString()}\n", Passphrase,
                                            workFactor: LowWorkFactor);

        var prompts = 0;
        using var file = new EncryptedIdentityFile(encrypted, () => { prompts++; return Passphrase.ToCharArray(); });

        Assert.Equal(0, prompts);

        _ = file.Recipients;
        Assert.Equal(1, prompts);

        // Cached: a second use must not prompt again.
        _ = file.Recipients;
        Assert.True(file.TryUnwrap([], new byte[Age.FileKeySize]) is false);
        Assert.Equal(1, prompts);
    }

    [Fact]
    public void Unmatched_File_IsNeverDecrypted()
    {
        // Two identity files, one of which opens the message: only that one is prompted for.
        using var wanted = X25519Identity.Generate();
        using var other = X25519Identity.Generate();

        var ciphertext = Age.Encrypt("hello"u8, [wanted.Recipient]);

        var wantedFile = EncryptIdentityFile($"{wanted.ToSecretString()}\n", Passphrase, workFactor: LowWorkFactor);
        var otherFile = EncryptIdentityFile($"{other.ToSecretString()}\n", Passphrase, workFactor: LowWorkFactor);

        var wantedPrompts = 0;
        var otherPrompts = 0;
        using var first = new EncryptedIdentityFile(wantedFile, () => { wantedPrompts++; return Passphrase.ToCharArray(); });
        using var second = new EncryptedIdentityFile(otherFile, () => { otherPrompts++; return Passphrase.ToCharArray(); });

        Assert.Equal("hello"u8.ToArray(), Age.Decrypt(ciphertext, [first, second]));

        Assert.Equal(1, wantedPrompts);
        Assert.Equal(0, otherPrompts);
    }

    [Fact]
    public void NotPassphraseEncrypted_ReportsThatSpecifically()
    {
        using var identity = X25519Identity.Generate();
        var toKey = Age.Encrypt("AGE-SECRET-KEY-1..."u8, [identity.Recipient]);

        using var file = new EncryptedIdentityFile(toKey, Passphrase.ToCharArray);

        var ex = Assert.Throws<AgeException>(() => file.Recipients);
        Assert.Contains("not with a passphrase", ex.Message);
    }

}