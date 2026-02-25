using Age;
using Age.Recipients;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

[MemoryDiagnoser]
public class RandomAccessBenchmarks
{
    private const int DataSize = 1_048_576; // 1 MB
    private const int ReadSize = 4096;

    private X25519Identity _identity = null!;
    private byte[] _ciphertext = null!;
    private AgeRandomAccess _randomAccess = null!;
    private long[] _randomOffsets = null!;

    [GlobalSetup]
    public void Setup()
    {
        _identity = X25519Identity.Generate();
        var recipient = _identity.Recipient;

        var plaintext = new byte[DataSize];
        Random.Shared.NextBytes(plaintext);

        using var encOut = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(plaintext), encOut, recipient);
        _ciphertext = encOut.ToArray();

        _randomAccess = new AgeRandomAccess(new MemoryStream(_ciphertext), _identity);

        // Pre-generate random offsets with fixed seed for reproducibility
        var rng = new Random(42);
        var maxOffset = _randomAccess.PlaintextLength - ReadSize;
        _randomOffsets = new long[256];
        for (var i = 0; i < _randomOffsets.Length; i++)
            _randomOffsets[i] = rng.NextInt64(0, maxOffset);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _randomAccess.Dispose();
        _identity.Dispose();
    }

    [Benchmark]
    public void SequentialRead()
    {
        Span<byte> buffer = stackalloc byte[ReadSize];
        long offset = 0;
        while (offset < _randomAccess.PlaintextLength)
        {
            _randomAccess.ReadAt(offset, buffer);
            offset += ReadSize;
        }
    }

    [Benchmark]
    public void RandomRead()
    {
        Span<byte> buffer = stackalloc byte[ReadSize];
        foreach (var offset in _randomOffsets)
            _randomAccess.ReadAt(offset, buffer);
    }
}
