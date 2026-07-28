using Age.Recipients;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

/// <summary>
/// Key generation, measured two ways because the two types put the work in different places.
/// </summary>
/// <remarks>
/// X25519 does its keygen in <c>Generate</c> and derives the recipient from an already-computed
/// public key. ML-KEM-768-X25519 is the reverse: <c>Generate</c> only fills a 32-byte seed, and the
/// ML-KEM keygen runs on first access to <c>Recipient</c> (cached thereafter). Comparing the two
/// <c>Generate</c> calls alone therefore reports post-quantum keygen as the faster of the two,
/// which is backwards — it has merely not happened yet. The …ToRecipient pair is the comparable
/// number: from nothing to a usable public key.
/// </remarks>
[MemoryDiagnoser]
public class KeyGenBenchmarks
{
    [Benchmark]
    public X25519Identity X25519Generate() => X25519Identity.Generate();

    [Benchmark]
    public MlKem768X25519Identity MlKem768X25519Generate() => MlKem768X25519Identity.Generate();

    [Benchmark]
    public X25519Recipient X25519ToRecipient() => X25519Identity.Generate().Recipient;

    [Benchmark]
    public MlKem768X25519Recipient MlKem768X25519ToRecipient() => MlKem768X25519Identity.Generate().Recipient;
}
