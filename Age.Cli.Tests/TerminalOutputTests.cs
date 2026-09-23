using System.Text;
using Age.Recipients;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// What may be printed to a terminal. Decrypted output is whatever the file's author chose, so
/// on a terminal it could carry escape sequences that drive it. go-age v1.3.2 (cmd/age, de96c8e)
/// buffers output bound for a terminal and refuses it unless it is valid UTF-8 without control
/// characters other than newline, carriage return and tab; "-o -" forces it anyway.
/// </summary>
public sealed class TerminalOutputTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-terminal-out-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Theory]
    [InlineData("plain text\n", true)]
    [InlineData("tabs\tand\r\nline endings\n", true)]
    [InlineData("unicode: grüße, 日本, 🙂\n", true)]
    [InlineData("\u001b[2J clear the screen", false)]
    [InlineData("bell\u0007", false)]
    [InlineData("C1 control\u009b31m", false)]
    [InlineData("nul\0byte", false)]
    public void IsPrintable_AllowsTextAndItsWhitespace_Only(string text, bool printable) =>
        Assert.Equal(printable, Terminal.IsPrintable(Encoding.UTF8.GetBytes(text)));

    [Fact]
    public void IsPrintable_RefusesInvalidUtf8() =>
        Assert.False(Terminal.IsPrintable([0x68, 0x69, 0xC3, 0x28]));

    [Fact]
    public void Decrypt_ToATerminal_RefusesBinary_AndPrintsNothing()
    {
        var (key, file) = Encrypted("\u001b[2Jgotcha"u8.ToArray());
        var terminal = new MemoryStream();

        var ex = Assert.Throws<AgeException>(() => Decrypt(key, file, outputPath: null, TerminalScreen(terminal)));

        Assert.Contains("-o -", ex.Message);
        Assert.Equal(0, terminal.Length);
    }

    [Fact]
    public void Decrypt_ToATerminal_PrintsText()
    {
        var (key, file) = Encrypted("hello\n"u8.ToArray());
        var terminal = new MemoryStream();

        Decrypt(key, file, outputPath: null, TerminalScreen(terminal));

        Assert.Equal("hello\n"u8.ToArray(), terminal.ToArray());
    }

    [Fact]
    public void Decrypt_WithDashOutput_WritesBinaryToTheTerminalAnyway()
    {
        var plaintext = new byte[] { 0x1b, 0x00, 0xff };
        var (key, file) = Encrypted(plaintext);
        var terminal = new MemoryStream();

        Decrypt(key, file, outputPath: "-", TerminalScreen(terminal));

        Assert.Equal(plaintext, terminal.ToArray());
        Assert.False(File.Exists(Path.Combine(Environment.CurrentDirectory, "-")));
    }

    [Fact]
    public void Decrypt_FromDashInput_ReadsStandardInput()
    {
        var (key, file) = Encrypted("from stdin\n"u8.ToArray());
        var stdout = new MemoryStream();
        var streams = new StandardStreams(() => new MemoryStream(File.ReadAllBytes(file)), () => stdout, OutputIsTerminal: false);

        Decrypt(key, "-", outputPath: null, streams);

        Assert.Equal("from stdin\n"u8.ToArray(), stdout.ToArray());
    }

    [Fact]
    public void Encrypt_ToATerminal_WithDashOutput_IsAllowedUnarmored()
    {
        using var identity = X25519Identity.Generate();
        var input = Path.Combine(_dir, "plain.txt");
        File.WriteAllText(input, "hi");
        var terminal = new MemoryStream();

        AgeCommand.Execute(encrypt: true, armor: false, passphrase: false, recipients: [identity.Recipient.ToString()],
            recipientFiles: [], identityFiles: [], outputPath: "-", inputPath: input, streams: TerminalScreen(terminal));

        Assert.StartsWith("age-encryption.org/v1\n", Encoding.ASCII.GetString(terminal.ToArray()));
    }

    [Fact]
    public void Encrypt_ToATerminal_Unarmored_IsRefused_WithTheOverride()
    {
        using var identity = X25519Identity.Generate();
        var input = Path.Combine(_dir, "plain.txt");
        File.WriteAllText(input, "hi");

        var ex = Assert.Throws<AgeException>(() => AgeCommand.Execute(encrypt: true, armor: false, passphrase: false,
            recipients: [identity.Recipient.ToString()], recipientFiles: [], identityFiles: [], outputPath: null,
            inputPath: input, streams: TerminalScreen(new MemoryStream())));

        Assert.Contains("-o -", ex.Message);
    }

    private static StandardStreams TerminalScreen(MemoryStream screen) =>
        new(() => throw new InvalidOperationException("stdin not expected"), () => screen, OutputIsTerminal: true);

    private (string Key, string File) Encrypted(byte[] plaintext)
    {
        using var identity = X25519Identity.Generate();
        var key = Path.Combine(_dir, $"{Guid.NewGuid()}.key");
        File.WriteAllText(key, identity.ToSecretString() + "\n");

        var file = Path.Combine(_dir, $"{Guid.NewGuid()}.age");
        using (var output = File.Create(file))
            AgeEncrypt.Encrypt(new MemoryStream(plaintext), output, identity.Recipient);

        return (key, file);
    }

    private static void Decrypt(string key, string input, string? outputPath, StandardStreams streams) =>
        AgeCommand.Execute(encrypt: false, armor: false, passphrase: false, recipients: [], recipientFiles: [],
            identityFiles: [key], outputPath: outputPath, inputPath: input, streams: streams);
}
