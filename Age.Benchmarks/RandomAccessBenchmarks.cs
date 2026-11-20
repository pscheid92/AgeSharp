using AgeSharp;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

[MemoryDiagnoser]
public class RandomAccessBenchmarks
{
    private const int DataSize = 1_048_576; // 1 MB
    private const int ReadSize = 4096;

    private X25519Identity _identity = null!;
    private byte[] _ciphertext = null!;
    private Stream _randomAccess = null!;
    private long[] _randomOffsets = null!;

    [GlobalSetup]
    public void Setup()
    {
        _identity = X25519Identity.Generate();
        var recipient = _identity.Recipient;

        var plaintext = new byte[DataSize];
        Random.Shared.NextBytes(plaintext);

        using var encOut = new MemoryStream();
        new Recipients(recipient).Encrypt(new MemoryStream(plaintext), encOut);
        _ciphertext = encOut.ToArray();

        // Seekable, because the ciphertext is: DecryptReader reads from any position.
        _randomAccess = new Identities(_identity).DecryptReader(new MemoryStream(_ciphertext));

        // Pre-generate random offsets with fixed seed for reproducibility
        var rng = new Random(42);
        var maxOffset = _randomAccess.Length - ReadSize;
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
        while (offset < _randomAccess.Length)
        {
            _randomAccess.Position = offset;
            _randomAccess.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            offset += ReadSize;
        }
    }

    [Benchmark]
    public void RandomRead()
    {
        Span<byte> buffer = stackalloc byte[ReadSize];
        foreach (var offset in _randomOffsets)
        {
            _randomAccess.Position = offset;
            _randomAccess.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        }
    }
}
