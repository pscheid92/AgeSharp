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
    public void APassphraseProtectedSshKey_Decrypts_OnceGivenItsPassphrase()
    {
        var keyFile = SshKey("ed25519_aes256ctr");
        var input = Write("secret.age", Encrypt("plaintext"u8.ToArray(),
            AgeKeygen.ParseSshRecipient(File.ReadAllText(SshKey("ed25519_plain.pub")))));
        var output = Path.Combine(_dir, "out");
        var before = Environment.GetEnvironmentVariable("AGE_PASSPHRASE");

        try
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", "hunter2");

            Assert.Equal(0, Decrypt(keyFile, input, output));
        }
        finally
        {
            Environment.SetEnvironmentVariable("AGE_PASSPHRASE", before);
        }

        Assert.Equal("plaintext"u8.ToArray(), File.ReadAllBytes(output));
    }

    [Fact]
    public void APassphraseProtectedSshKey_EncryptsToItself_WithoutItsPassphrase()
    {
        var input = Write("plain.txt", "plaintext"u8.ToArray());
        var encrypted = Path.Combine(_dir, "secret.age");
        var before = Environment.GetEnvironmentVariable("AGE_PASSPHRASE");

        try
        {
            // Nothing to answer a prompt with: were the passphrase asked for, this would fail.
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
