using Age.Fuzz;

// Age.Fuzz — a mutation fuzzer over AgeSharp's parsers and the plugin protocol; see README.md.
//
//   run [--seconds N] [--seed N] [--out DIR] [TARGET ...]   every target, or those named, in parallel
//   replay TARGET FILE                            one input, to reproduce a finding
//   profile TARGET                                every seed, timed, slowest first
//   worker TARGET SECONDS OUT SEED                one target in this process (what run starts)
return args switch
{
    [] => Orchestrator.Run([]),
    ["run", .. var rest] => Orchestrator.Run(rest),
    ["replay", var target, var file] => Replay(target, file),
    ["profile", var target] => Profile(target),
    ["worker", var target, var seconds, var outDir, var seed] => Worker.Run(target, int.Parse(seconds), outDir, int.Parse(seed)),
    _ => Usage(),
};

static int Replay(string name, string file)
{
    var target = Targets.Create(name, Repo.Root());
    try
    {
        Console.WriteLine(target.Run(File.ReadAllBytes(file)));
        return 0;
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex);
        return 1;
    }
}

// Times every seed of a target, slowest first: what makes a target slow.
static int Profile(string name)
{
    var target = Targets.Create(name, Repo.Root());
    var seeds = target.Seeds().Where(s => s.Length <= Mutator.MaxLength).ToList();
    foreach (var seed in seeds)
        target.Run(seed); // warm up, so the times are not the JIT's
    var times = new List<(double Ms, string Start, string Outcome)>();
    foreach (var seed in seeds)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var outcome = target.Run(seed);
        times.Add((clock.Elapsed.TotalMilliseconds, Start(seed), outcome));
    }
    Console.WriteLine($"{times.Count} seeds, {times.Sum(t => t.Ms):F0} ms in all");
    foreach (var (ms, start, outcome) in times.OrderByDescending(t => t.Ms).Take(15))
        Console.WriteLine($"  {ms,8:F1} ms  {start,-40}  {outcome}");
    return 0;
}

// The seed's first line that says what it is: a stanza, or else its first line.
static string Start(byte[] seed)
{
    var lines = System.Text.Encoding.Latin1.GetString(seed[..Math.Min(seed.Length, 400)]).Split('\n');
    var line = lines.FirstOrDefault(l => l.StartsWith("-> ", StringComparison.Ordinal)) ?? lines[0];
    return new string(line.Take(40).Select(c => char.IsControl(c) ? '.' : c).ToArray());
}

static int Usage()
{
    Console.Error.WriteLine("usage: Age.Fuzz [run [--seconds N] [--seed N] [--out DIR] [TARGET ...]] | replay TARGET FILE | profile TARGET");
    Console.Error.WriteLine($"targets: {string.Join(", ", Targets.Names)}");
    return 2;
}
