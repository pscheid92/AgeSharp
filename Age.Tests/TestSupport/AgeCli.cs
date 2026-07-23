using System.Diagnostics;
using System.Text;

namespace Age.Tests;

/// <summary>
/// Locates the reference <c>age</c> / <c>age-keygen</c> CLI binaries used by the interop
/// tests by searching <c>PATH</c>, and drives <c>age</c> for encrypt/decrypt so interop tests
/// read as data rather than repeated process plumbing. CI installs age onto PATH explicitly;
/// local shells get it via Homebrew's <c>shellenv</c>. When age is not on PATH the tests skip
/// cleanly rather than falsely passing.
/// </summary>
internal static class AgeCli
{
    public static string? AgePath { get; } = Find("age");
    public static string? AgeKeygenPath { get; } = Find("age-keygen");

    public static bool Available => AgePath is not null;
    public static bool KeygenAvailable => AgeKeygenPath is not null;

    /// <summary>Encrypts <paramref name="plaintext"/> with the reference age CLI to one or more recipients.</summary>
    public static byte[] Encrypt(byte[] plaintext, bool armored, params string[] recipients)
    {
        var input = WriteTemp(plaintext);
        var output = Path.GetTempFileName();
        try
        {
            var args = new List<string>();
            if (armored)
                args.Add("-a");
            foreach (var recipient in recipients)
            {
                args.Add("-r");
                args.Add(recipient);
            }
            args.Add("-o");
            args.Add(output);
            args.Add(input);

            Run(args);
            return File.ReadAllBytes(output);
        }
        finally
        {
            TryDelete(input);
            TryDelete(output);
        }
    }

    /// <summary>Decrypts <paramref name="ciphertext"/> with the reference age CLI using the given identity-file contents.</summary>
    public static byte[] Decrypt(string identityFileText, byte[] ciphertext)
    {
        var key = WriteTemp(Encoding.UTF8.GetBytes(identityFileText));
        var input = WriteTemp(ciphertext);
        var output = Path.GetTempFileName();
        try
        {
            Run(["-d", "-i", key, "-o", output, input]);
            return File.ReadAllBytes(output);
        }
        finally
        {
            TryDelete(key);
            TryDelete(input);
            TryDelete(output);
        }
    }

    private static void Run(IEnumerable<string> args)
    {
        // Only stderr is redirected: every call passes -o, so the tool writes its result to a
        // file and nothing to stdout, which sidesteps the unread-pipe deadlock entirely.
        var psi = new ProcessStartInfo(AgePath!)
        {
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var proc = Process.Start(psi)!;
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        if (proc.ExitCode != 0)
            throw new InvalidOperationException($"age exited with code {proc.ExitCode}: {stderr}");
    }

    private static string WriteTemp(byte[] data)
    {
        var path = Path.GetTempFileName();
        File.WriteAllBytes(path, data);
        return path;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // Best-effort cleanup of a scratch file; a leaked temp file must not fail a test.
        }
    }

    private static string? Find(string name)
    {
        var fileName = OperatingSystem.IsWindows() ? name + ".exe" : name;

        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = Path.Combine(dir, fileName);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
