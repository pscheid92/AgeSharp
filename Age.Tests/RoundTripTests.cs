using System.Diagnostics;
using Age;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class RoundTripTests
{
    [Fact]
    public void X25519_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = "Hello, age!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_RoundTrip_Empty()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = Array.Empty<byte>();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_RoundTrip_Large()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        // Test with data larger than one chunk (> 64 KiB)
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_RoundTrip_ExactChunkSize()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        // Exactly 64 KiB
        var plaintext = new byte[64 * 1024];
        new Random(42).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void Scrypt_RoundTrip()
    {
        var passphrase = "correct horse battery staple";
        var recipient = new ScryptRecipient(passphrase, workFactor: 10);

        var plaintext = "Hello, scrypt age!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, recipient);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_MultipleRecipients()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();

        var plaintext = "multi-recipient test"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, id1.Recipient, id2.Recipient);

        // Decrypt with first identity
        encOutput.Position = 0;
        using var decOutput1 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput1, id1);
        Assert.Equal(plaintext, decOutput1.ToArray());

        // Decrypt with second identity
        encOutput.Position = 0;
        using var decOutput2 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput2, id2);
        Assert.Equal(plaintext, decOutput2.ToArray());
    }

    [Fact]
    public void X25519_KeyRoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var identityStr = identity.ToString();
        var recipientStr = identity.Recipient.ToString();

        using var parsed = AgeKeygen.ParseIdentity(identityStr);
        var parsedRecipient = AgeKeygen.ParseRecipient(recipientStr);

        Assert.Equal(identityStr, parsed.ToString());
        Assert.Equal(recipientStr, parsedRecipient.ToString());
    }

    [Fact]
    public void Interop_EncryptWithCSharp_DecryptWithAgeCli()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return; // Skip if age CLI not available

        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;
        var plaintext = "Hello from C# AgeSharp!"u8.ToArray();

        // Encrypt with C#
        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        var ciphertext = encOutput.ToArray();
        var tempCipher = Path.GetTempFileName();
        var tempKey = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempCipher, ciphertext);
            File.WriteAllText(tempKey, identity.ToString());

            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-d -i {tempKey} {tempCipher}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            Assert.Equal(0, proc.ExitCode);
            Assert.Equal("Hello from C# AgeSharp!", output);
        }
        finally
        {
            File.Delete(tempCipher);
            File.Delete(tempKey);
        }
    }

    [Fact]
    public void Interop_EncryptWithAgeCli_DecryptWithCSharp()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return; // Skip if age CLI not available

        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        var tempCipher = Path.GetTempFileName();
        try
        {
            // Encrypt with age CLI
            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-r {recipientStr} -o {tempCipher}")
            {
                RedirectStandardInput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            proc.StandardInput.Write("Hello from age CLI!");
            proc.StandardInput.Close();
            proc.WaitForExit();
            Assert.Equal(0, proc.ExitCode);

            // Decrypt with C#
            var ciphertext = File.ReadAllBytes(tempCipher);
            using var decInput = new MemoryStream(ciphertext);
            using var decOutput = new MemoryStream();
            AgeEncrypt.Decrypt(decInput, decOutput, identity);

            var result = System.Text.Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("Hello from age CLI!", result);
        }
        finally
        {
            File.Delete(tempCipher);
        }
    }
}
