using System.Diagnostics;
using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// The output must not be a file the command reads. go-age v1.3.2 (cmd/age, dbe5773) refuses
/// -o naming the input, an identity file or a recipients file, by path or as the same file
/// through a link. Here, age -d -i key.txt -o key.txt overwrote the private key with the
/// plaintext and exited 0.
/// </summary>
public sealed class OutputAliasTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-alias-").FullName;
    private readonly X25519Identity _identity = X25519Identity.Generate();

    public void Dispose()
    {
        _identity.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public void Decrypt_IntoItsIdentityFile_IsRefused_AndTheKeySurvives()
    {
        var key = Write("key.txt", _identity.ToSecretString() + "\n");
        var file = EncryptedFile("plaintext");

        AssertRefused(() => Run(decrypt: true, identityFile: key, output: key, input: file));

        Assert.Equal(_identity.ToSecretString() + "\n", File.ReadAllText(key));
    }

    [Fact]
    public void Encrypt_IntoItsRecipientsFile_IsRefused_AndTheFileSurvives()
    {
        var recipients = Write("recipients.txt", _identity.Recipient + "\n");
        var input = Write("plain.txt", "plaintext");

        AssertRefused(() => Run(decrypt: false, recipientsFile: recipients, output: recipients, input: input));

        Assert.Equal(_identity.Recipient + "\n", File.ReadAllText(recipients));
    }

    [Fact]
    public void Encrypt_IntoItsInput_IsRefused_AsTheSameFile()
    {
        var input = Write("plain.txt", "plaintext");

        // Relative against absolute, so the paths differ as text.
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, input);

        AssertRefused(() => Run(decrypt: false, recipient: _identity.Recipient.ToString(), output: relative, input: input));
        Assert.Equal("plaintext", File.ReadAllText(input));
    }

    [SkippableTheory]
    [InlineData("symlink")]
    [InlineData("hard link")]
    public void Decrypt_IntoALinkToItsIdentityFile_IsRefused(string link)
    {
        Skip.If(OperatingSystem.IsWindows(), "creating links needs a privilege on Windows");

        var key = Write("key.txt", _identity.ToSecretString() + "\n");
        var alias = Path.Combine(_dir, "alias.txt");

        if (link == "symlink")
            File.CreateSymbolicLink(alias, key);
        else
            Process.Start("ln", [key, alias])!.WaitForExit();

        AssertRefused(() => Run(decrypt: true, identityFile: key, output: alias, input: EncryptedFile("plaintext")));
        Assert.Equal(_identity.ToSecretString() + "\n", File.ReadAllText(key));
    }

    [Fact]
    public void Output_ToAnotherExistingFile_IsAllowed()
    {
        var key = Write("key.txt", _identity.ToSecretString() + "\n");
        var output = Write("out.txt", "old contents");

        Run(decrypt: true, identityFile: key, output: output, input: EncryptedFile("plaintext"));

        Assert.Equal("plaintext", File.ReadAllText(output));
    }

    private static void AssertRefused(Action run)
    {
        var ex = Assert.Throws<AgeException>(run);
        Assert.StartsWith("input and output file are the same", ex.Message);
    }

    private string EncryptedFile(string plaintext)
    {
        var path = Path.Combine(_dir, $"{Guid.NewGuid()}.age");
        using var output = File.Create(path);
        AgeEncrypt.Encrypt(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(plaintext)), output, _identity.Recipient);
        return path;
    }

    private string Write(string name, string contents)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, contents);
        return path;
    }

    private static void Run(bool decrypt, string output, string input,
        string? identityFile = null, string? recipientsFile = null, string? recipient = null) =>
        AgeCommand.Execute(encrypt: !decrypt, armor: false, passphrase: false,
            recipients: recipient is null ? [] : [recipient],
            recipientFiles: recipientsFile is null ? [] : [recipientsFile],
            identityFiles: identityFile is null ? [] : [identityFile],
            outputPath: output, inputPath: input);
}
