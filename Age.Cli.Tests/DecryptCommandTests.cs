using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// <c>age -d</c>, driven through <see cref="AgeCommand.Execute"/> with files on disk.
/// </summary>
public sealed class DecryptCommandTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-decrypt-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void PassphraseFile_WithIdentityFile_SaysToUsePassphrase()
    {
        var input = Write("secret.age", Encrypt("plaintext"u8.ToArray(), new ScryptRecipient("pw", workFactor: 10)));
        using var identity = X25519Identity.Generate();
        var identityFile = Write("key.txt", identity.ToSecretString() + "\n");

        var ex = Assert.Throws<AgeException>(() => Decrypt(identityFile, input, Path.Combine(_dir, "out")));

        Assert.Contains("use -p", ex.Message);
    }

    [Fact]
    public void Passphrase_FromTheEnvironment_Decrypts()
    {
        var input = Write("secret.age", Encrypt("plaintext"u8.ToArray(), new ScryptRecipient("pw", workFactor: 10)));
        var output = Path.Combine(_dir, "out");
        var before = Environment.GetEnvironmentVariable("AGE_PASSPHRASE");

        try
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", "pw");

            Assert.Equal(0, AgeCommand.Execute(encrypt: false, armor: false, passphrase: true,
                recipients: [], recipientFiles: [], identityFiles: [], outputPath: output, inputPath: input));
        }
        finally
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", before);
        }

        Assert.Equal("plaintext"u8.ToArray(), File.ReadAllBytes(output));
    }

    [Fact]
    public void APassphraseProtectedSshKey_IsUnlockedWithWhatIsTypedOnTheTerminal()
    {
        var keyFile = SshKey("ed25519_aes256ctr");
        var ciphertext = Encrypt("plaintext"u8.ToArray(), AgeKeygen.ParseSshRecipient(File.ReadAllText(SshKey("ed25519_plain.pub"))));
        var terminalInput = new MemoryStream("hunter2\n"u8.ToArray());
        var terminalOutput = new MemoryStream();
        var before = Environment.GetEnvironmentVariable("AGE_PASSPHRASE");

        try
        {
            // Passphrase mode's variable, set to something wrong: the SSH key must not use it.
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", "not the key's passphrase");

            var identity = AgeCommand.ParseSshKeyFile(keyFile, File.ReadAllText(keyFile),
                () => new StreamTerminal(terminalInput, terminalOutput, () => new Released()));

            using var decrypted = new MemoryStream();
            AgeEncrypt.Decrypt(new MemoryStream(ciphertext), decrypted, identity);
            Assert.Equal("plaintext"u8.ToArray(), decrypted.ToArray());
        }
        finally
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", before);
        }

        Assert.StartsWith($"Enter passphrase for \"{keyFile}\": ", System.Text.Encoding.UTF8.GetString(terminalOutput.ToArray()));
    }

    // With several -i files, the error has to say which one; go-age names it (cmd/age/parse.go).
    [Fact]
    public void WhenThePassphraseCannotBeRead_TheErrorNamesTheKeyFile()
    {
        var keyFile = SshKey("ed25519_aes256ctr");
        var ciphertext = Encrypt("plaintext"u8.ToArray(), AgeKeygen.ParseSshRecipient(File.ReadAllText(SshKey("ed25519_plain.pub"))));
        var identity = AgeCommand.ParseSshKeyFile(keyFile, File.ReadAllText(keyFile),
            () => throw new AgeException("cannot ask for input: no terminal"));

        var ex = Assert.Throws<AgeException>(() => AgeEncrypt.Decrypt(new MemoryStream(ciphertext), new MemoryStream(), identity));

        Assert.Contains($"could not read passphrase for \"{keyFile}\"", ex.Message);
        Assert.Contains("no terminal", ex.Message);
    }

    [Fact]
    public void AMalformedSshKeyFile_IsNamedInTheError()
    {
        var keyFile = SshKey("ecdsa_aes256ctr");

        var ex = Assert.Throws<AgeException>(() => AgeCommand.ParseSshKeyFile(keyFile, File.ReadAllText(keyFile), () => throw new InvalidOperationException()));

        Assert.StartsWith($"malformed SSH identity in \"{keyFile}\": ", ex.Message);
    }

    [Fact]
    public void APassphraseProtectedSshKey_IsNotAskedFor_WhenTheFileIsForSomeoneElse()
    {
        var keyFile = SshKey("ed25519_aes256ctr");
        using var someoneElse = X25519Identity.Generate();
        var ciphertext = Encrypt("plaintext"u8.ToArray(), someoneElse.Recipient);
        var identity = AgeCommand.ParseSshKeyFile(keyFile, File.ReadAllText(keyFile),
            () => throw new InvalidOperationException("the terminal was opened"));

        Assert.Throws<NoIdentityMatchException>(() => AgeEncrypt.Decrypt(new MemoryStream(ciphertext), new MemoryStream(), identity));
    }

    [Fact]
    public void APassphraseProtectedSshKey_EncryptsToItself_WithoutItsPassphrase()
    {
        var input = Write("plain.txt", "plaintext"u8.ToArray());
        var encrypted = Path.Combine(_dir, "secret.age");
        var before = Environment.GetEnvironmentVariable("AGE_PASSPHRASE");

        try
        {
            // Nothing that could answer a prompt: encrypting to the key needs only its public half.
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", null);

            Assert.Equal(0, AgeCommand.Execute(encrypt: true, armor: false, passphrase: false,
                recipients: [], recipientFiles: [], identityFiles: [SshKey("ed25519_aes256ctr")],
                outputPath: encrypted, inputPath: input));
        }
        finally
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", before);
        }

        Assert.Equal(0, Decrypt(SshKey("ed25519_plain"), encrypted, Path.Combine(_dir, "out")));
        Assert.Equal("plaintext"u8.ToArray(), File.ReadAllBytes(Path.Combine(_dir, "out")));
    }

    private sealed class Released : IDisposable
    {
        public void Dispose() { }
    }

    private static string SshKey(string name) =>
        Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name);

    private int Decrypt(string identityFile, string input, string output) =>
        AgeCommand.Execute(encrypt: false, armor: false, passphrase: false,
            recipients: [], recipientFiles: [], identityFiles: [identityFile],
            outputPath: output, inputPath: input);

    private static byte[] Encrypt(byte[] plaintext, IRecipient recipient)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(plaintext), output, recipient);
        return output.ToArray();
    }

    private string Write(string name, byte[] contents)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, contents);
        return path;
    }

    private string Write(string name, string contents) => Write(name, System.Text.Encoding.UTF8.GetBytes(contents));
}
