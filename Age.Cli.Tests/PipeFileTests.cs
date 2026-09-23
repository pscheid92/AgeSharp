using System.Diagnostics;
using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// Key files and outputs can be pipes, as with a shell's process substitution:
/// <c>age -d -i &lt;(pass show age-key)</c>. A pipe has no length and must not be opened more than
/// the command itself opens it — an open for reading blocks until a writer appears.
/// </summary>
public sealed class PipeFileTests : IDisposable
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-pipes-").FullName;
    private readonly X25519Identity _identity = X25519Identity.Generate();

    public void Dispose()
    {
        _identity.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    [SkippableFact]
    public void IdentityFile_ThatIsAPipe_IsRead()
    {
        Skip.If(OperatingSystem.IsWindows(), "named pipes are a Unix concept here");

        var key = Fifo("key.pipe");
        var writer = Feed(key, _identity.ToSecretString() + "\n");
        var output = Path.Combine(_dir, "out.txt");

        Finish(() => Execute(decrypt: true, identityFiles: [key], output: output, input: EncryptedFile("plaintext")));

        Assert.True(writer.Wait(Patience));
        Assert.Equal("plaintext", File.ReadAllText(output));
    }

    [SkippableFact]
    public void RecipientsFile_ThatIsAPipe_IsRead()
    {
        Skip.If(OperatingSystem.IsWindows(), "named pipes are a Unix concept here");

        var recipients = Fifo("recipients.pipe");
        var writer = Feed(recipients, _identity.Recipient + "\n");
        var output = Path.Combine(_dir, "out.age");
        var input = Path.Combine(_dir, "plain.txt");
        File.WriteAllText(input, "plaintext");

        Finish(() => Execute(decrypt: false, recipientFiles: [recipients], output: output, input: input));

        Assert.True(writer.Wait(Patience));
        Assert.Equal("plaintext", Decrypt(File.ReadAllBytes(output)));
    }

    [SkippableFact]
    public void Output_ThatIsAPipe_IsWrittenWithoutHanging()
    {
        Skip.If(OperatingSystem.IsWindows(), "named pipes are a Unix concept here");

        var output = Fifo("out.pipe");
        var received = Path.Combine(_dir, "received.txt");

        // The reader is cat, as in a shell pipeline. A .NET reader would take .NET's shared
        // advisory lock, which on Linux applies to a FIFO too, and collide with the output's
        // exclusive create — a clash no real reader causes.
        using var cat = Process.Start("/bin/sh", ["-c", "cat \"$0\" > \"$1\"", output, received])!;

        Finish(() => Execute(decrypt: true, identityFiles: [KeyFile()], output: output, input: EncryptedFile("plaintext")));

        Assert.True(cat.WaitForExit(Patience));
        Assert.Equal("plaintext", File.ReadAllText(received));
    }

    // Run on another thread, so a hang fails the test instead of stalling the run.
    private static void Finish(Action run) =>
        Assert.True(Task.Run(run).Wait(Patience), "the command did not finish");

    private string Fifo(string name)
    {
        var path = Path.Combine(_dir, name);
        Process.Start("mkfifo", [path])!.WaitForExit();
        return path;
    }

    private static Task Feed(string pipe, string contents) =>
        Task.Run(() => File.WriteAllText(pipe, contents));

    private string KeyFile()
    {
        var path = Path.Combine(_dir, "key.txt");
        File.WriteAllText(path, _identity.ToSecretString() + "\n");
        return path;
    }

    private string EncryptedFile(string plaintext)
    {
        var path = Path.Combine(_dir, $"{Guid.NewGuid()}.age");
        using var output = File.Create(path);
        AgeEncrypt.Encrypt(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(plaintext)), output, _identity.Recipient);
        return path;
    }

    private string Decrypt(byte[] ciphertext)
    {
        using var plaintext = new MemoryStream();
        AgeEncrypt.Decrypt(new MemoryStream(ciphertext), plaintext, _identity);
        return System.Text.Encoding.UTF8.GetString(plaintext.ToArray());
    }

    private static void Execute(bool decrypt, string output, string input,
        string[]? identityFiles = null, string[]? recipientFiles = null) =>
        AgeCommand.Execute(encrypt: !decrypt, armor: false, passphrase: false, recipients: [],
            recipientFiles: recipientFiles ?? [], identityFiles: identityFiles ?? [],
            outputPath: output, inputPath: input);
}
