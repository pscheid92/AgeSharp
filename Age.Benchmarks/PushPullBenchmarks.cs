using BenchmarkDotNet.Attributes;

namespace AgeSharp.Benchmarks;

/// <summary>
///     Compares the three encryption shapes over the same plaintext: the eager
///     one-shot <see cref="Age.Encrypt(System.IO.Stream, System.IO.Stream, System.ReadOnlySpan{IRecipient})" />,
///     the push writer <see cref="Age.EncryptWriter(System.IO.Stream, System.ReadOnlySpan{IRecipient})" />,
///     and the pull reader <see cref="Age.EncryptReader(System.IO.Stream, IRecipient, System.ReadOnlySpan{IRecipient})" />
///     .
///     All three run the same chunked STREAM path, so the numbers isolate the per-shape
///     buffering overhead.
/// </summary>
[MemoryDiagnoser]
public class PushPullBenchmarks
{
    [Params(65_536, 1_048_576)] public int DataSize;

    private X25519Identity _identity = null!;
    private byte[] _plaintext = null!;

    [GlobalSetup]
    public void Setup()
    {
        _identity = X25519Identity.Generate();
        _plaintext = new byte[DataSize];
        Random.Shared.NextBytes(_plaintext);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _identity.Dispose();
    }

    [Benchmark]
    public void OneShot()
    {
        using var output = new MemoryStream();
        Age.Encrypt(new MemoryStream(_plaintext), output, _identity.Recipient);
    }

    [Benchmark]
    public void Push_EncryptWriter()
    {
        using var output = new MemoryStream();
        using var stream = Age.EncryptWriter(output, _identity.Recipient);
        stream.Write(_plaintext);
    }

    [Benchmark]
    public void Pull_EncryptReader()
    {
        using var output = new MemoryStream();
        using var stream = Age.EncryptReader(new MemoryStream(_plaintext), _identity.Recipient);
        stream.CopyTo(output);
    }
}