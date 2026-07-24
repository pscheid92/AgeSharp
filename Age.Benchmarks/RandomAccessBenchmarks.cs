using AgeSharp;
using BenchmarkDotNet.Attributes;

namespace AgeSharp.Benchmarks;

[MemoryDiagnoser]
public class RandomAccessBenchmarks
{
    private const int DataSize = 1_048_576; // 1 MB
    private const int ReadSize = 4096;

    private X25519Identity _identity = null!;
    private byte[] _ciphertext = null!;
    private Stream _reader = null!;
    private long _plaintextLength;
    private long[] _randomOffsets = null!;
    private long _sink; // consumes Read results so they aren't optimized away

    [GlobalSetup]
    public void Setup()
    {
        _identity = X25519Identity.Generate();
        var recipient = _identity.Recipient;

        var plaintext = new byte[DataSize];
        Random.Shared.NextBytes(plaintext);

        using var encOut = new MemoryStream();
        Age.Encrypt(new MemoryStream(plaintext), encOut, recipient);
        _ciphertext = encOut.ToArray();

        _reader = Age.OpenRead(new MemoryStream(_ciphertext), _identity);
        _plaintextLength = _reader.Length;

        // Pre-generate random offsets with fixed seed for reproducibility
        var rng = new Random(42);
        var maxOffset = _plaintextLength - ReadSize;
        _randomOffsets = new long[256];
        for (var i = 0; i < _randomOffsets.Length; i++)
            _randomOffsets[i] = rng.NextInt64(0, maxOffset);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _reader.Dispose();
        _identity.Dispose();
    }

    [Benchmark]
    public void SequentialRead()
    {
        Span<byte> buffer = stackalloc byte[ReadSize];
        _reader.Position = 0;
        int read;
        while ((read = _reader.Read(buffer)) > 0)
            _sink += read;
    }

    [Benchmark]
    public void RandomRead()
    {
        Span<byte> buffer = stackalloc byte[ReadSize];
        foreach (var offset in _randomOffsets)
        {
            _reader.Position = offset;
            _sink += _reader.Read(buffer);
        }
    }

    // Tiny reads within a chunk: with the one-chunk cache each 64 KiB chunk is
    // decrypted once regardless of how many small reads land inside it. Without
    // the cache this would re-decrypt the chunk on every 64-byte Read.
    [Benchmark]
    public void SmallSequentialReads()
    {
        Span<byte> buffer = stackalloc byte[64];
        _reader.Position = 0;
        int read;
        while ((read = _reader.Read(buffer)) > 0)
            _sink += read;
    }
}
