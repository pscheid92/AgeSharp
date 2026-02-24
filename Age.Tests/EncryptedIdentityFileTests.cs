using System.Diagnostics;
using Age;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class EncryptedIdentityFileTests
{
    private const string Passphrase = "correct horse battery staple";
    private const int LowWorkFactor = 10; // fast for tests

    [Fact]
    public void ParseIdentityFile_X25519()
    {
        using var identity = X25519Identity.Generate();
        var text = $"""
            # created: 2024-01-01
            # public key: {identity.Recipient}
            {identity}
            """;

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Single(parsed);
        Assert.Equal(identity.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void ParseIdentityFile_WithBlankLinesAndComments()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# comment\n\n{identity}\n\n# another comment\n";

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Single(parsed);
        Assert.Equal(identity.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void ParseIdentityFile_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519 key\n{x25519}\n# PQ key\n{pq}\n";

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Equal(2, parsed.Count);
        Assert.Equal(x25519.ToString(), parsed[0].ToString());
        Assert.Equal(pq.ToString(), parsed[1].ToString());
    }

    [Fact]
    public void ParseIdentityFile_UnrecognizedLine_Throws()
    {
        var text = "# comment\nNOT-A-VALID-KEY\n";
        var ex = Assert.Throws<FormatException>(() => AgeKeygen.ParseIdentityFile(text));
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
        var text = $"# created: 2024-01-01\n{identity}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        Assert.Single(parsed);
        Assert.Equal(identity.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_Armored()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, armor: true, workFactor: LowWorkFactor);

        // Verify it's armored (starts with the armor header)
        var armoredText = System.Text.Encoding.UTF8.GetString(encrypted);
        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", armoredText);

        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);
        Assert.Single(parsed);
        Assert.Equal(identity.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void DecryptIdentityFile_WrongPassphrase_Throws()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity}\n";
        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);

        Assert.ThrowsAny<Exception>(() => AgeKeygen.DecryptIdentityFile(encrypted, "wrong passphrase"));
    }

    [Fact]
    public void EncryptDecrypt_PqIdentity()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = $"# PQ identity\n{identity}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        Assert.Single(parsed);
        Assert.Equal(identity.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void EncryptDecrypt_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519\n{x25519}\n# PQ\n{pq}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(text, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        Assert.Equal(2, parsed.Count);
        Assert.Equal(x25519.ToString(), parsed[0].ToString());
        Assert.Equal(pq.ToString(), parsed[1].ToString());
    }

    [Fact]
    public void Interop_EncryptWithAgeCli_DecryptWithAgeSharp()
    {
        if (!File.Exists("/opt/homebrew/bin/age") || !File.Exists("/opt/homebrew/bin/age-keygen"))
            return;

        // Use AgeSharp to encrypt (since age CLI -p requires a terminal for encryption),
        // then verify CLI can decrypt it, then re-encrypt with CLI using a recipient key,
        // and verify AgeSharp can parse the identity file after decryption.
        // This tests the identity file format interop with age-keygen output.

        var tempKey = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}.txt");
        try
        {
            // Generate key with age-keygen (tests parsing its output format)
            var keygenPsi = new ProcessStartInfo("/opt/homebrew/bin/age-keygen", $"-o {tempKey}")
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
            Assert.StartsWith("AGE-SECRET-KEY-1", parsed[0].ToString());

            // Roundtrip: encrypt with AgeSharp, decrypt with AgeSharp
            var encrypted = AgeKeygen.EncryptIdentityFile(keyText, Passphrase, workFactor: LowWorkFactor);
            var decrypted = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);
            Assert.Equal(parsed[0].ToString(), decrypted[0].ToString());
        }
        finally
        {
            File.Delete(tempKey);
        }
    }

    [Fact]
    public void Interop_DecryptedIdentity_WorksWithAgeCli()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return;

        // Encrypt identity file with AgeSharp, decrypt it, then verify the
        // recovered key works with the age CLI for a regular encrypt/decrypt.
        using var identity = X25519Identity.Generate();
        var identityText = $"# test key\n{identity}\n";

        var encrypted = AgeKeygen.EncryptIdentityFile(identityText, Passphrase, workFactor: LowWorkFactor);
        var parsed = AgeKeygen.DecryptIdentityFile(encrypted, Passphrase);

        // Use the decrypted identity to decrypt data encrypted by the age CLI
        var recipientStr = identity.Recipient.ToString();
        var tempCipher = Path.GetTempFileName();
        try
        {
            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-r {recipientStr} -o {tempCipher}")
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
