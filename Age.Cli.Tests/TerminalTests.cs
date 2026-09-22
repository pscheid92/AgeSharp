using System.Text;
using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// Prompts are answered on the terminal, never on standard input: stdin carries the data in
/// <c>cat file.age | age -d -p</c>, where reading a passphrase from it used to crash in
/// Console.ReadKey. Nothing here touches the real terminal of whoever runs the tests.
/// </summary>
public class TerminalTests
{
    [Fact]
    public void Open_PrefersTheControllingTerminal_EvenWhenStdinIsOne()
    {
        var tty = new StreamTerminal(new MemoryStream(), new MemoryStream(), NoHiding);

        Assert.Same(tty, Terminal.Open(() => tty, stdinIsTerminal: true));
    }

    [Fact]
    public void Open_WithoutAControllingTerminal_FallsBackToStdin_WhenStdinIsATerminal() =>
        Assert.IsType<ConsoleTerminal>(Terminal.Open(() => null, stdinIsTerminal: true));

    [Fact]
    public void Open_WithNoTerminalAtAll_SaysSoInsteadOfReadingTheData()
    {
        var ex = Assert.Throws<AgeException>(() => Terminal.Open(() => null, stdinIsTerminal: false));

        Assert.Contains("not a terminal", ex.Message);
    }

    [Fact]
    public void ReadLine_ShowsThePromptOnTheTerminal_AndReturnsTheAnswer()
    {
        var output = new MemoryStream();
        using var terminal = new StreamTerminal(Input("yubikey 5\r\nnext line\n"), output, NoHiding);

        Assert.Equal("yubikey 5", terminal.ReadLine("Which token? ", secret: false));
        Assert.Equal("Which token? ", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void ReadLine_Secret_IsReadWhileInputIsHidden_ThenEndsTheLine()
    {
        var output = new MemoryStream();
        var hiding = new HidingProbe();
        using var terminal = new StreamTerminal(new ObservedStream(Input("correct horse\n"), hiding), output, hiding.Hide);

        Assert.Equal("correct horse", terminal.ReadLine("Passphrase: ", secret: true));
        Assert.True(hiding.EveryReadWasHidden);
        Assert.False(hiding.Hidden);

        // The Enter the user typed was not echoed, so the terminal needs its newline.
        Assert.Equal("Passphrase: \n", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void ReadLine_Public_DoesNotHideInput()
    {
        var hiding = new HidingProbe();
        using var terminal = new StreamTerminal(Input("yes\n"), new MemoryStream(), hiding.Hide);

        terminal.ReadLine("Continue? ", secret: false);

        Assert.Equal(0, hiding.Times);
    }

    [Fact]
    public void ReadLine_WhenTheTerminalCloses_Fails()
    {
        using var terminal = new StreamTerminal(Input(""), new MemoryStream(), NoHiding);

        Assert.Throws<AgeException>(() => terminal.ReadLine("Passphrase: ", secret: true));
    }

    private static MemoryStream Input(string text) => new(Encoding.UTF8.GetBytes(text));

    private static IDisposable NoHiding() => new HidingProbe.Restore(() => { });

    private sealed class HidingProbe
    {
        public bool Hidden { get; private set; }
        public int Times { get; private set; }
        public bool EveryReadWasHidden { get; private set; } = true;

        public IDisposable Hide()
        {
            Hidden = true;
            Times++;
            return new Restore(() => Hidden = false);
        }

        public void ObserveRead() => EveryReadWasHidden &= Hidden;

        public sealed class Restore(Action restore) : IDisposable
        {
            public void Dispose() => restore();
        }
    }

    private sealed class ObservedStream(Stream inner, HidingProbe probe) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            probe.ObserveRead();
            return inner.Read(buffer, offset, count);
        }

        public override int ReadByte()
        {
            probe.ObserveRead();
            return inner.ReadByte();
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
