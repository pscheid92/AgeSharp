using System.Text;
using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// Key files are read into memory, so their size is bounded as go-age v1.3.2 bounds it (cmd/age,
/// 418c7ac): recipients and identity files at 16 MiB, SSH private keys below 16 KiB. A file of
/// several gigabytes named with -i or -R was read whole.
/// </summary>
public sealed class KeyFileSizeTests : IDisposable
{
    private const int SixteenMiB = 16 * 1024 * 1024;
    private const int SixteenKiB = 16 * 1024;

    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-keysize-").FullName;
    private readonly X25519Identity _identity = X25519Identity.Generate();

    public void Dispose()
    {
        _identity.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public void RecipientsFile_UpTo16MiB_IsRead(int bytesOver, bool accepted)
    {
        var recipients = Padded("recipients.txt", _identity.Recipient + "\n", SixteenMiB + bytesOver);
        var input = Write("plain.txt", "hi");

        void Encrypt() => AgeCommand.Execute(encrypt: true, armor: false, passphrase: false, recipients: [],
            recipientFiles: [recipients], identityFiles: [], outputPath: Path.Combine(_dir, "out.age"), inputPath: input);

        if (accepted)
            Encrypt();
        else
            Assert.EndsWith("recipients file is too long", Assert.Throws<AgeException>(Encrypt).Message);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public void IdentityFile_UpTo16MiB_IsRead(int bytesOver, bool accepted)
    {
        var key = Padded("key.txt", _identity.ToSecretString() + "\n", SixteenMiB + bytesOver);

        if (accepted)
            Assert.Equal("hi", Decrypt(key));
        else
            Assert.Equal("identities file is too long", Assert.Throws<AgeException>(() => Decrypt(key)).Message);
    }

    [Fact]
    public void SshKeyFile_Of16KiBOrMore_IsRefused()
    {
        var pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + new string('A', SixteenKiB) + "\n-----END OPENSSH PRIVATE KEY-----\n";
        var key = Write("id_ed25519", pem);

        var ex = Assert.Throws<AgeException>(() => Decrypt(key));

        Assert.EndsWith("file too long", ex.Message);
    }

    [Fact]
    public void EncryptedIdentityFile_Over16MiB_IsRefused()
    {
        var key = Write("key.age", "age-encryption.org/v1\n" + new string('#', SixteenMiB));

        var ex = Assert.Throws<AgeException>(() => Decrypt(key));

        Assert.EndsWith("file too long", ex.Message);
    }

    private string Decrypt(string identityFile)
    {
        var file = Path.Combine(_dir, "in.age");
        using (var output = File.Create(file))
            AgeEncrypt.Encrypt(new MemoryStream("hi"u8.ToArray()), output, _identity.Recipient);

        var plaintext = Path.Combine(_dir, $"{Guid.NewGuid()}.txt");
        AgeCommand.Execute(encrypt: false, armor: false, passphrase: false, recipients: [], recipientFiles: [],
            identityFiles: [identityFile], outputPath: plaintext, inputPath: file);
        return File.ReadAllText(plaintext);
    }

    // The key line, then comment lines up to exactly the requested size.
    private string Padded(string name, string keyLine, int size)
    {
        var text = new StringBuilder(keyLine);
        while (text.Length < size)
        {
            var remaining = size - text.Length;
            text.Append('#').Append('x', Math.Min(remaining, 4096) - (remaining > 1 ? 2 : 1));
            if (remaining > 1)
                text.Append('\n');
        }

        Assert.Equal(size, text.Length);
        return Write(name, text.ToString());
    }

    private string Write(string name, string contents)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, contents);
        return path;
    }
}
