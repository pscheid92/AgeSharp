using System.Diagnostics;
using System.Reflection;

namespace Age.Fuzz;

/// <summary>
/// Runs each target in a worker process of its own, all at once, starting a worker again when it
/// ends on a hang, and reports what they found. Exits 1 when anything was found.
/// </summary>
internal static class Orchestrator
{
    public static int Run(string[] args)
    {
        var seconds = 60;
        var seed = Random.Shared.Next(1, 1_000_000);
        var outDir = Path.Combine(Path.GetTempPath(), "agesharp-fuzz", DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        var names = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--seconds" when i + 1 < args.Length:
                    seconds = int.Parse(args[++i]);
                    break;
                case "--seed" when i + 1 < args.Length:
                    seed = int.Parse(args[++i]);
                    break;
                case "--out" when i + 1 < args.Length:
                    outDir = Path.GetFullPath(args[++i]);
                    break;
                case var name when Targets.Names.Contains(name):
                    names.Add(name);
                    break;
                default:
                    Console.Error.WriteLine($"unknown argument \"{args[i]}\"; targets: {string.Join(", ", Targets.Names)}");
                    return 2;
            }
        }

        if (names.Count == 0)
            names.AddRange(Targets.Names);

        Directory.CreateDirectory(outDir);
        Console.WriteLine($"fuzzing {string.Join(", ", names)} for {seconds} s each, seed {seed}; findings go to {outDir}");

        var results = names.Select(name => Task.Run(() => RunTarget(name, seconds, outDir, seed))).ToArray();
        Task.WaitAll(results);

        var failed = false;
        foreach (var result in results.Select(r => r.Result))
        {
            Console.WriteLine();
            Console.Write(result.Output);
            foreach (var code in result.ExitCodes.Where(c => c is not (0 or 1 or Worker.HangExitCode)))
            {
                // A worker that died (a stack overflow, an exception on another thread) saved nothing.
                Console.WriteLine($"{result.Name}: the worker died with exit code {code}; its output is above");
                failed = true;
            }
        }

        var findings = Directory.Exists(Path.Combine(outDir, "findings"))
            ? Directory.GetFiles(Path.Combine(outDir, "findings"), "*.txt", SearchOption.AllDirectories)
            : [];
        Console.WriteLine();
        Console.WriteLine(findings.Length == 0 ? "no findings" : $"{findings.Length} findings:");
        foreach (var finding in findings.Order())
            Console.WriteLine($"  {finding}: {File.ReadLines(finding).First()}");

        return failed || findings.Length > 0 ? 1 : 0;
    }

    private sealed record Result(string Name, List<int> ExitCodes, string Output);

    // A worker that hung starts again with the next seed, so it does not run into the same input.
    private static Result RunTarget(string name, int seconds, string outDir, int first)
    {
        var deadline = Stopwatch.StartNew();
        var codes = new List<int>();
        var output = new System.Text.StringBuilder();

        for (var seed = first; ; seed++)
        {
            var left = Math.Max(1, seconds - (int)deadline.Elapsed.TotalSeconds);
            var (code, text) = Start(["worker", name, left.ToString(), outDir, seed.ToString()]);
            codes.Add(code);
            output.Append(text);

            if (code != Worker.HangExitCode || deadline.Elapsed.TotalSeconds >= seconds)
                return new Result(name, codes, output.ToString());
        }
    }

    // Starts this program again as a worker, through dotnet when that is what runs it.
    private static (int Code, string Output) Start(string[] args)
    {
        var self = Environment.ProcessPath!;
        var info = new ProcessStartInfo(self) { RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(self) == "dotnet")
            info.ArgumentList.Add(Assembly.GetEntryAssembly()!.Location);
        foreach (var arg in args)
            info.ArgumentList.Add(arg);

        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
