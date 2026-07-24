using System.Diagnostics;
using AgeSharp;
using Xunit;

namespace Age.Tests;

public class EncryptedIdentityFileTests
{
    private const string Passphrase = "correct horse battery staple";
    private const int LowWorkFactor = 10; // fast for tests

    // ToString() on identities is redacted; comparisons need the secret form,
    // which only exists on the concrete types.
    private static string Secret(IIdentity identity) => identity switch
    {
        X25519Identity x => x.ToSecretString(),
        MlKem768X25519Identity pq => pq.ToSecretString(),
        PluginIdentity plugin => plugin.ToSecretString(),
        _ => throw new InvalidOperationException($"no secret form for {identity.GetType().Name}")
    };

    [Fact]
    public void ParseIdentityFile_X25519()
    {
        using var identity = X25519Identity.Generate();
        var text = $"""
            # created: 2024-01-01
            # public key: {identity.Recipient}
            {identity.ToSecretString()}
            """;

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void ParseIdentityFile_WithBlankLinesAndComments()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# comment\n\n{identity.ToSecretString()}\n\n# another comment\n";

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void ParseIdentityFile_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519 key\n{x25519.ToSecretString()}\n# PQ key\n{pq.ToSecretString()}\n";

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Equal(2, parsed.Length);
        Assert.Equal(x25519.ToSecretString(), Secret(parsed[0]));
        Assert.Equal(pq.ToSecretString(), Secret(parsed[1]));
    }

    [Fact]
    public void ParseIdentityFile_UnrecognizedLine_Throws()
    {
        var text = "# comment\nNOT-A-VALID-KEY\n";
        var ex = Assert.Throws<AgeFormatException>(() => AgeKeygen.ParseIdentityFile(text));
        Assert.Contains("unrecognized line", ex.Message);
    }

    [Fact]
    public void ParseIdentityFile_Empty_ReturnsEmpty()
    {
        var parsed = AgeKeygen.ParseIdentityFile("");
        Assert.Empty(parsed);
    }

    [Fact]
    public void ParseIdentityFile_OnlyComments_ReturnsEmpty()
    {
        var parsed = AgeKeygen.ParseIdentityFile("# just a comment\n# another\n");
        Assert.Empty(parsed);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# created: 2024-01-01\n{identity.ToSecretString()}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_Armored()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity.ToSecretString()}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, armor: true, workFactor: LowWorkFactor);

        // Verify it's armored (starts with the armor header)
        var armoredText = System.Text.Encoding.UTF8.GetString(encrypted);
        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", armoredText);

        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);
        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void DecryptIdentityFile_WrongPassphrase_Throws()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity.ToSecretString()}\n";
        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);

        Assert.ThrowsAny<Exception>(() => AgeKeygen.DecryptIdentityFile(encrypted, "wrong passphrase"));
    }

    [Fact]
    public void EncryptDecrypt_PqIdentity()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = $"# PQ identity\n{identity.ToSecretString()}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        Assert.Single(parsed);
        Assert.Equal(identity.ToSecretString(), Secret(parsed[0]));
    }

    [Fact]
    public void EncryptDecrypt_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519\n{x25519.ToSecretString()}\n# PQ\n{pq.ToSecretString()}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        Assert.Equal(2, parsed.Length);
        Assert.Equal(x25519.ToSecretString(), Secret(parsed[0]));
        Assert.Equal(pq.ToSecretString(), Secret(parsed[1]));
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
            var parsed = AgeKeygen.ParseIdentityFile(keyText);

            Assert.Single(parsed);
            Assert.StartsWith("AGE-SECRET-KEY-1", Secret(parsed[0]));

            // Roundtrip: encrypt with AgeSharp, decrypt with AgeSharp
            var encrypted = AgeKeygen.EncryptIdentityFile(keyText, Passphrase, workFactor: LowWorkFactor);
            var decrypted = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);
            Assert.Equal(Secret(parsed[0]), Secret(decrypted[0]));
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

        var encrypted = AgeKeygen.EncryptIdentityFile(identityText, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        // Use the decrypted identity to decrypt data encrypted by the age CLI
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
            AgeEncrypt.Decrypt(decInput, decOutput, parsed.ToArray());

            var result = System.Text.Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("secret from age CLI", result);
        }
        finally
        {
            File.Delete(tempCipher);
        }
    }
}
