using System.Diagnostics;
using System.Text;

namespace Age.Tests;

/// <summary>
/// Drives another implementation's CLI — Go's <c>age</c> or Rust's <c>rage</c>, which take the
/// same flags — for encrypt and decrypt, so interop tests read as data rather than repeated
/// process plumbing. The binary is looked up on <c>PATH</c>; when it is missing, tests skip
/// cleanly rather than falsely passing.
/// </summary>
internal sealed class ReferenceCli(string name, IReadOnlyDictionary<string, string>? environment = null)
{
    public string Name { get; } = name;
    public string? Path { get; } = Find(name);
    public bool Available => Path is not null;

    /// <summary>Encrypts <paramref name="plaintext"/> to one or more recipients.</summary>
    public byte[] Encrypt(byte[] plaintext, bool armored, params string[] recipients)
    {
        var input = WriteTemp(plaintext);
        var output = System.IO.Path.GetTempFileName();
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

    /// <summary>Decrypts <paramref name="ciphertext"/> using the given identity-file contents.</summary>
    public byte[] Decrypt(string identityFileText, byte[] ciphertext)
    {
        var key = WriteTemp(Encoding.UTF8.GetBytes(identityFileText));
        var input = WriteTemp(ciphertext);
        var output = System.IO.Path.GetTempFileName();
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

    private void Run(IEnumerable<string> args)
    {
        // Only stderr is redirected: every call passes -o, so the tool writes its result to a
        // file and nothing to stdout, which sidesteps the unread-pipe deadlock entirely.
        var psi = new ProcessStartInfo(Path!)
        {
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        foreach (var (key, value) in environment ?? new Dictionary<string, string>())
            psi.Environment[key] = value;

        using var proc = Process.Start(psi)!;
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        if (proc.ExitCode != 0)
            throw new InvalidOperationException($"{Name} exited with code {proc.ExitCode}: {stderr}");
    }

    private static string WriteTemp(byte[] data)
    {
        var path = System.IO.Path.GetTempFileName();
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

    internal static string? Find(string name)
    {
        var fileName = OperatingSystem.IsWindows() ? name + ".exe" : name;

        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = System.IO.Path.Combine(dir, fileName);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
