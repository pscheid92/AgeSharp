using System.Text;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>A plugin's questions are asked and answered on the terminal it is given.</summary>
public class CliPluginCallbacksTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RequestValue_AsksOnTheTerminal(bool secret)
    {
        var (callbacks, output, hidden) = Answering("123456\n");

        Assert.Equal("123456", callbacks.RequestValue("Enter PIN for YubiKey", secret));
        Assert.Equal(secret ? "Enter PIN for YubiKey: \n" : "Enter PIN for YubiKey: ", output());
        Assert.Equal(secret, hidden());
    }

    [Theory]
    [InlineData("y\n", true)]
    [InlineData("YES\n", true)]
    [InlineData("n\n", false)]
    [InlineData("\n", false)]
    [InlineData("maybe\ny\n", true)]
    public void Confirm_TakesYesOrNo_AndAsksAgainOtherwise(string answers, bool expected)
    {
        var (callbacks, output, _) = Answering(answers);

        Assert.Equal(expected, callbacks.Confirm("Touch your key", "done", "cancel"));
        Assert.StartsWith("Touch your key [y: done / n: cancel] (y/N): ", output());
        Assert.Equal(answers.StartsWith("maybe"), output().Contains("Please answer y or n"));
    }

    [Fact]
    public void DisplayMessage_GoesToStandardError()
    {
        using var console = new ConsoleCapture();

        new CliPluginCallbacks(() => throw new InvalidOperationException("no terminal needed")).DisplayMessage("insert your key");

        Assert.Equal("insert your key" + Environment.NewLine, console.Error);
    }

    // One input shared across questions, as a real terminal is; each question opens a fresh view.
    private static (CliPluginCallbacks Callbacks, Func<string> Output, Func<bool> Hidden) Answering(string answers)
    {
        var input = new MemoryStream(Encoding.UTF8.GetBytes(answers));
        var output = new MemoryStream();
        var hidden = false;

        var callbacks = new CliPluginCallbacks(() => new StreamTerminal(input, output, () =>
        {
            hidden = true;
            return new Released();
        }));

        return (callbacks, () => Encoding.UTF8.GetString(output.ToArray()), () => hidden);
    }

    private sealed class Released : IDisposable
    {
        public void Dispose() { }
    }
}
