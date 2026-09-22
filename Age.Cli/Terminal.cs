using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Age.Cli;

/// <summary>Somewhere to ask the user a question and read one line of answer.</summary>
internal interface ITerminal : IDisposable
{
    /// <summary>Shows <paramref name="prompt"/> and reads one line; a secret answer is not echoed.</summary>
    string ReadLine(string prompt, bool secret);
}

/// <summary>
/// Where the CLI asks the user things: the terminal, never standard input.
/// </summary>
/// <remarks>
/// Standard input carries the data in <c>cat file.age | age -d -p</c>, so a prompt that read from
/// it would read the ciphertext — and Console.ReadKey, which the prompts used, crashes outright
/// on redirected input. As in go-age, the controlling terminal is opened directly, and preferred
/// even when stdin is a terminal too; stdin is the fallback only when it is one.
/// </remarks>
internal static class Terminal
{
    public static string ReadSecret(string prompt) => Read(prompt, secret: true);

    public static string ReadLine(string prompt) => Read(prompt, secret: false);

    private static string Read(string prompt, bool secret)
    {
        using var terminal = Open(OpenControllingTerminal, stdinIsTerminal: !Console.IsInputRedirected);
        return terminal.ReadLine(prompt, secret);
    }

    internal static ITerminal Open(Func<ITerminal?> openControllingTerminal, bool stdinIsTerminal) =>
        openControllingTerminal()
        ?? (stdinIsTerminal
            ? new ConsoleTerminal()
            : throw new AgeException(
                "cannot ask for input: standard input is not a terminal, and no terminal is available"));

    private static ITerminal? OpenControllingTerminal()
    {
        // go-age opens CONIN$/CONOUT$ on Windows. Until that is done here, a redirected stdin on
        // Windows gets Open's error rather than a crash.
        if (OperatingSystem.IsWindows())
            return null;

        FileStream tty;

        try
        {
            tty = new FileStream("/dev/tty", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, bufferSize: 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // No controlling terminal, as under CI or a service manager.
            return null;
        }

        return new StreamTerminal(tty, tty, SttyEcho.Hide, owner: tty);
    }
}

/// <summary>A terminal reached through streams: /dev/tty in production, memory in tests.</summary>
/// <param name="hideInput">Turns echo off until the returned value is disposed.</param>
internal sealed class StreamTerminal(Stream input, Stream output, Func<IDisposable> hideInput, IDisposable? owner = null)
    : ITerminal
{
    public string ReadLine(string prompt, bool secret)
    {
        output.Write(Encoding.UTF8.GetBytes(prompt));
        output.Flush();

        if (!secret)
            return ReadAnswer();

        using (hideInput())
        {
            try
            {
                return ReadAnswer();
            }
            finally
            {
                // The Enter that ended the answer was not echoed either.
                output.Write("\n"u8);
                output.Flush();
            }
        }
    }

    /// <summary>
    /// One line, byte by byte so nothing past it is consumed. The buffer grows by copying, so
    /// each outgrown one is zeroed: it holds part of what may be a passphrase.
    /// </summary>
    private string ReadAnswer()
    {
        var buffer = new byte[128];
        var length = 0;

        try
        {
            int b;

            while ((b = input.ReadByte()) is >= 0 and not '\n')
            {
                if (length == buffer.Length)
                    buffer = Grow(buffer);

                buffer[length++] = (byte)b;
            }

            if (b < 0 && length == 0)
                throw new AgeException("no answer: the terminal closed");

            if (length > 0 && buffer[length - 1] == '\r')
                length--;

            return Encoding.UTF8.GetString(buffer, 0, length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        static byte[] Grow(byte[] old)
        {
            var grown = new byte[old.Length * 2];
            old.CopyTo(grown, 0);
            CryptographicOperations.ZeroMemory(old);
            return grown;
        }
    }

    public void Dispose() => owner?.Dispose();
}

/// <summary>Standard input and error, for when stdin is the terminal and /dev/tty is not there.</summary>
internal sealed class ConsoleTerminal : ITerminal
{
    public string ReadLine(string prompt, bool secret)
    {
        Console.Error.Write(prompt);

        if (!secret)
            return Console.ReadLine() ?? throw new AgeException("no answer: the terminal closed");

        var answer = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.Error.WriteLine();
                    return answer.ToString();

                case ConsoleKey.Backspace when answer.Length > 0:
                    answer.Remove(answer.Length - 1, 1);
                    break;

                default:
                    if (key.KeyChar != '\0')
                        answer.Append(key.KeyChar);
                    break;
            }
        }
    }

    public void Dispose() { }
}

/// <summary>
/// Turns echo off on the controlling terminal with stty, and restores the exact settings it found.
/// </summary>
/// <remarks>
/// stty rather than termios through P/Invoke: the struct's layout differs between platforms
/// (macOS widens its flags to 64 bits), and stty -g / -echo are POSIX. The saved settings are
/// passed as an argument, never spliced into the shell command. If echo cannot be turned off,
/// the secret is not read at all — showing it would be worse than failing.
/// </remarks>
internal static class SttyEcho
{
    public static IDisposable Hide()
    {
        var saved = Stty("-g").Trim();
        Stty("-echo");
        return new Restorer(saved);
    }

    private static string Stty(params string[] args)
    {
        var start = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };

        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("stty \"$@\" < /dev/tty");
        start.ArgumentList.Add("sh");

        foreach (var arg in args)
            start.ArgumentList.Add(arg);

        using var stty = Process.Start(start) ?? throw CannotHide();
        var output = stty.StandardOutput.ReadToEnd();
        stty.WaitForExit();

        return stty.ExitCode == 0 ? output : throw CannotHide();
    }

    private static AgeException CannotHide() =>
        new("cannot turn off echo on the terminal, so the secret would be shown; not reading it");

    /// <summary>Restores on dispose, and on Ctrl+C or termination while the answer is being typed.</summary>
    private sealed class Restorer : IDisposable
    {
        private readonly string _saved;
        private readonly PosixSignalRegistration _interrupt;
        private readonly PosixSignalRegistration _terminate;
        private int _restored;

        public Restorer(string saved)
        {
            _saved = saved;
            _interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, _ => Restore());
            _terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => Restore());
        }

        public void Dispose()
        {
            _interrupt.Dispose();
            _terminate.Dispose();
            Restore();
        }

        private void Restore()
        {
            if (Interlocked.Exchange(ref _restored, 1) == 0)
                Stty(_saved);
        }
    }
}
