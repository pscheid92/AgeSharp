using System.Diagnostics;
using System.Security.Cryptography;

namespace Age.Fuzz;

/// <summary>
/// Fuzzes one target: runs every seed, then mutants of the pool until the time is up. There is
/// no coverage feedback; an input that ends in an outcome not seen before joins the pool, which
/// stands in for it. A finding — an exception the documentation does not allow, a broken
/// oracle, an input still running after ten seconds — is saved, one input per kind.
/// </summary>
internal static class Worker
{
    /// <summary>What a worker exits with after saving a hang, for the orchestrator to start it again.</summary>
    public const int HangExitCode = 3;

    private const int PoolLimit = 20_000;
    private static readonly TimeSpan HangAfter = TimeSpan.FromSeconds(10);

    public static int Run(string name, int seconds, string outDir, int seed)
    {
        var target = Targets.Create(name, Repo.Root());
        var rng = new Random(seed);
        var pool = target.Seeds().Where(s => s.Length <= Mutator.MaxLength).ToList();
        var seedCount = pool.Count;
        var counts = new Dictionary<string, long>();
        var findings = new Findings(Path.Combine(outDir, "findings", name), name);
        var running = new Running();

        var watchdog = new Thread(() =>
        {
            while (true)
            {
                Thread.Sleep(1000);
                if (running.Input() is { } input && running.Elapsed() > HangAfter)
                {
                    findings.Save("hang", input, $"still running after {HangAfter.TotalSeconds} s");
                    Environment.Exit(HangExitCode);
                }
            }
        }) { IsBackground = true };
        watchdog.Start();

        var clock = Stopwatch.StartNew();
        long execs = 0;

        void Exec(byte[] input)
        {
            running.Start(input);
            string outcome;
            try
            {
                outcome = target.Run(input);
            }
            catch (Finding f)
            {
                outcome = "finding: " + f.Kind;
                findings.Save(f.Kind, input, f.Message);
            }
            catch (Exception ex)
            {
                var kind = $"{ex.GetType().Name} {Frame(ex)}";
                outcome = "finding: " + kind;
                findings.Save(kind, input, ex.ToString());
            }
            running.Stop();
            execs++;

            if (counts.TryAdd(outcome, 0))
            {
                if (pool.Count < PoolLimit)
                    pool.Add(input);
                else
                    pool[seedCount + rng.Next(pool.Count - seedCount)] = input;
            }
            counts[outcome]++;
        }

        foreach (var s in pool.ToList())
            Exec(s);
        while (clock.Elapsed.TotalSeconds < seconds)
            Exec(Mutator.Mutate(pool, rng));

        Console.WriteLine($"{name}: {execs:N0} inputs in {clock.Elapsed.TotalSeconds:F0} s from {seedCount} seeds, {counts.Count} outcomes, {findings.Count} findings");
        Console.WriteLine($"  {counts.GetValueOrDefault("ok"),12:N0}  ok");
        foreach (var (outcome, n) in counts.Where(kv => kv.Key != "ok").OrderByDescending(kv => kv.Value).Take(12))
            Console.WriteLine($"  {n,12:N0}  {outcome}");
        return findings.Count == 0 ? 0 : 1;
    }

    // The first of AgeSharp's own frames, without the file and line.
    private static string Frame(Exception ex)
    {
        var line = ex.StackTrace?.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("at AgeSharp.", StringComparison.Ordinal)) ?? "";
        var at = line.IndexOf(" in ", StringComparison.Ordinal);
        return at < 0 ? line : line[..at];
    }

    // The input being run and since when, for the watchdog.
    private sealed class Running
    {
        private byte[]? _input;
        private long _started;

        public void Start(byte[] input)
        {
            Volatile.Write(ref _input, input);
            Interlocked.Exchange(ref _started, Stopwatch.GetTimestamp());
        }

        public void Stop() => Volatile.Write(ref _input, null);

        public byte[]? Input() => Volatile.Read(ref _input);

        public TimeSpan Elapsed() => Stopwatch.GetElapsedTime(Interlocked.Read(ref _started));
    }

    private sealed class Findings(string dir, string target)
    {
        private readonly HashSet<string> _kinds = [];

        public int Count
        {
            get
            {
                lock (_kinds)
                    return _kinds.Count;
            }
        }

        public void Save(string kind, byte[] input, string detail)
        {
            lock (_kinds)
            {
                if (!_kinds.Add(kind))
                    return;
                Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, Convert.ToHexString(SHA256.HashData(input))[..16].ToLowerInvariant());
                File.WriteAllBytes(path + ".bin", input);
                File.WriteAllText(path + ".txt", $"{kind}\n\n{detail}\n");
                Console.WriteLine($"{target}: FINDING {kind}");
            }
        }
    }
}
