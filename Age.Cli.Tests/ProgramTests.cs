using Xunit;

namespace Age.Cli.Tests;

/// <summary>The real entry point: what a user's mistake looks like on standard error.</summary>
public sealed class ProgramTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("agesharp-program-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void MissingFile_IsNamed_AndIsNotCalledABug()
    {
        var missing = Path.Combine(_dir, "no-such-key.txt");

        var (exit, error) = Run("-d", "-i", missing, Path.Combine(_dir, "in.age"));

        Assert.Equal(1, exit);
        Assert.Equal($"age: no such file: {missing}", error.TrimEnd());
    }

    [Fact]
    public void MissingOutputDirectory_IsReported_AndIsNotCalledABug()
    {
        var input = Path.Combine(_dir, "plain.txt");
        File.WriteAllText(input, "plaintext");
        using var identity = Age.Recipients.X25519Identity.Generate();

        var (exit, error) = Run("-r", identity.Recipient.ToString(), "-o", Path.Combine(_dir, "missing", "out.age"), input);

        Assert.Equal(1, exit);
        Assert.StartsWith("age: ", error);
        Assert.DoesNotContain("bug", error);
    }

    private static (int Exit, string Error) Run(params string[] args)
    {
        using var console = new ConsoleCapture();
        var exit = (int)typeof(UserError).Assembly.EntryPoint!.Invoke(null, [args])!;
        return (exit, console.Error);
    }
}
