using Age.Recipients;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

[MemoryDiagnoser]
public class KeyGenBenchmarks
{
    [Benchmark]
    public X25519Identity X25519Generate() => X25519Identity.Generate();

    [Benchmark]
    public MlKem768X25519Identity MlKem768X25519Generate() => MlKem768X25519Identity.Generate();
}
