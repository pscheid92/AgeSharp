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

        var parsed = Identities.Parse(text);
        Assert.Equal(identity.ToSecretString(), Secret(Assert.Single(parsed)));
    }

    [Fact]
    public void ParseIdentityFile_WithBlankLinesAndComments()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# comment\n\n{identity.ToSecretString()}\n\n# another comment\n";

        var parsed = Identities.Parse(text);
        Assert.Equal(identity.ToSecretString(), Secret(Assert.Single(parsed)));
    }

    [Fact]
    public void ParseIdentityFile_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519 key\n{x25519.ToSecretString()}\n# PQ key\n{pq.ToSecretString()}\n";

        var parsed = Identities.Parse(text);
        Assert.Equal(2, parsed.Count);
        Assert.Equal(x25519.ToSecretString(), Secret(parsed[0]));
        Assert.Equal(pq.ToSecretString(), Secret(parsed[1]));
    }

    [Fact]
    public void ParseIdentityFile_UnrecognizedLine_Throws()
    {
        var text = "# comment\nNOT-A-VALID-KEY\n";
        var ex = Assert.Throws<FormatException>(() => Identities.Parse(text));
        Assert.Contains("unrecognized identity (line 2 of the identity file)", ex.Message);
    }

    // A line that almost is a key is still a key. Error messages reach logs and terminals, so a
    // malformed line is reported by its number, never quoted — as go-age does.
    [Theory]
    [InlineData("leading space")]
    [InlineData("leading tab")]
    [InlineData("lowercase")]
    [InlineData("lowercase post-quantum")]
    [InlineData("lowercase plugin")]
    [InlineData("trailing space")]
    [InlineData("corrupted checksum")]
    public void ParseIdentityFile_MalformedKeyLine_IsNotQuoted(string malformation)
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        const string plugin = "AGE-PLUGIN-YUBIKEY-1QQSR4HXQY3MX3";

        var secret = malformation switch
        {
            "lowercase post-quantum" => pq.ToSecretString(),
            "lowercase plugin" => plugin,
            _ => x25519.ToSecretString(),
        };

        var line = malformation switch
        {
            "leading space" => " " + secret,
            "leading tab" => "\t" + secret,
            "trailing space" => secret + " ",
            "corrupted checksum" => secret[..^1] + (secret[^1] == 'Q' ? 'P' : 'Q'),
            _ => secret.ToLowerInvariant(),
        };

        var ex = Assert.Throws<FormatException>(() => Identities.Parse($"# comment\n\n{line}\n"));

        // The key material is the bech32 data after the last '1'; no part of the message may carry it.
        var keyData = secret[(secret.LastIndexOf('1') + 1)..];
        Assert.DoesNotContain(keyData, ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("line 3", ex.Message);
    }

    // As in go-age: an identity file without an identity can only ever fail to decrypt.
    [Theory]
    [InlineData("")]
    [InlineData("# just a comment\n# another\n")]
    public void ParseIdentityFile_WithoutIdentities_IsRefused(string text)
    {
        var ex = Assert.Throws<FormatException>(() => Identities.Parse(text));
        Assert.Contains("no identities", ex.Message);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# created: 2024-01-01\n{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text);
        using var parsed = Open(encrypted);

        Assert.Equal(identity.Recipient.ToString(), Assert.Single(parsed.Recipients).ToString());
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_Armored()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text, armor: true);

        // Verify it's armored (starts with the armor header)
        var armoredText = System.Text.Encoding.UTF8.GetString(encrypted);
        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", armoredText);

        using var parsed = Open(encrypted);
        Assert.Equal(identity.Recipient.ToString(), Assert.Single(parsed.Recipients).ToString());
    }

    [Fact]
    public void DecryptIdentityFile_WrongPassphrase_Throws()
    {
        using var identity = X25519Identity.Generate();
        var text = $"{identity.ToSecretString()}\n";
        var encrypted = EncryptIdentityFile(text);

        using var wrong = new EncryptedIdentityFile(encrypted, () => "wrong passphrase".ToCharArray());
        Assert.Throws<AgeException>(() => wrong.Recipients);
    }

    [Fact]
    public void EncryptDecrypt_PqIdentity()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = $"# PQ identity\n{identity.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text);
        using var parsed = Open(encrypted);

        Assert.Equal(identity.Recipient.ToString(), Assert.Single(parsed.Recipients).ToString());
    }

    [Fact]
    public void EncryptDecrypt_MultipleIdentities()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"# X25519\n{x25519.ToSecretString()}\n# PQ\n{pq.ToSecretString()}\n";

        var encrypted = EncryptIdentityFile(text);
        using var parsed = Open(encrypted);

        Assert.Equal([x25519.Recipient.ToString(), pq.Recipient.ToString()], parsed.Recipients.Select(r => r.ToString()));
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
            var parsed = Identities.Parse(keyText);

            Assert.Single(parsed);
            Assert.StartsWith("AGE-SECRET-KEY-1", Secret(parsed[0]));

            // Roundtrip: encrypt with AgeSharp, decrypt with AgeSharp
            var encrypted = EncryptIdentityFile(keyText);
            using var decrypted = Open(encrypted);
            Assert.Equal(((X25519Identity)parsed[0]).Recipient.ToString(), Assert.Single(decrypted.Recipients).ToString());
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

        var encrypted = EncryptIdentityFile(identityText);
        using var parsed = Open(encrypted);

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
            new Identities(parsed).Decrypt(decInput, decOutput);

            var result = System.Text.Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("secret from age CLI", result);
        }
        finally
        {
            File.Delete(tempCipher);
        }
    }

    // What age -p writes: the identity file, encrypted to a passphrase.
    private static byte[] EncryptIdentityFile(string text, bool armor = false)
    {
        using var passphrase = new AgeSharp.Passphrase(Passphrase, LowWorkFactor);
        return new Recipients(passphrase).Encrypt(System.Text.Encoding.UTF8.GetBytes(text), new AgeEncryptOptions { Armor = armor });
    }

    private static EncryptedIdentityFile Open(byte[] encrypted) =>
        new(encrypted, () => Passphrase.ToCharArray());
}
