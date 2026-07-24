using System.Buffers.Binary;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Parameters;
using BclChaCha = System.Security.Cryptography.ChaCha20Poly1305;
using BcChaCha = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace AgeSharp.Benchmarks;

// Compares the platform (BCL) ChaCha20-Poly1305 against BouncyCastle's managed one
// in AgeSharp's streaming hot-path pattern: construct once, encrypt per 64 KiB chunk.
// The question this answers: does moving the payload AEAD to BouncyCastle (to gain
// browser support) cost meaningful throughput and/or reintroduce per-chunk allocations?
[ShortRunJob]
[MemoryDiagnoser]
public class ChaChaImplBenchmarks
{
    private const int ChunkSize = 64 * 1024;   // age STREAM chunk size
    private const int TagSize = 16;
    private const int NonceSize = 12;

    [Params(65_536, 1_048_576, 16_777_216)]    // 64 KiB, 1 MiB, 16 MiB payloads
    public int PayloadSize;

    private byte[] _key = null!;
    private byte[] _plaintext = null!;
    private byte[] _output = null!;
    private byte[] _nonce = null!;

    private BclChaCha _bcl = null!;
    private BcChaCha _bc = null!;
    private KeyParameter _bcKey = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _plaintext = new byte[PayloadSize];
        RandomNumberGenerator.Fill(_plaintext);
        _output = new byte[ChunkSize + TagSize];
        _nonce = new byte[NonceSize];

        _bcl = new BclChaCha(_key);
        _bc = new BcChaCha();
        _bcKey = new KeyParameter(_key);
    }

    [GlobalCleanup]
    public void Cleanup() => _bcl.Dispose();

    // Platform ChaCha20-Poly1305: span-based one-shot per chunk, no per-chunk allocation.
    [Benchmark(Baseline = true)]
    public void Bcl()
    {
        long counter = 0;
        for (var offset = 0; offset < _plaintext.Length; offset += ChunkSize, counter++)
        {
            var len = Math.Min(ChunkSize, _plaintext.Length - offset);
            WriteNonce(_nonce, counter);
            _bcl.Encrypt(_nonce, _plaintext.AsSpan(offset, len),
                _output.AsSpan(0, len), _output.AsSpan(len, TagSize));
        }
    }

    // BouncyCastle: the idiomatic AEAD flow, Init with fresh AeadParameters per chunk.
    [Benchmark]
    public void BouncyCastle()
    {
        long counter = 0;
        for (var offset = 0; offset < _plaintext.Length; offset += ChunkSize, counter++)
        {
            var len = Math.Min(ChunkSize, _plaintext.Length - offset);
            WriteNonce(_nonce, counter);
            _bc.Init(true, new AeadParameters(_bcKey, TagSize * 8, _nonce));
            var written = _bc.ProcessBytes(_plaintext, offset, len, _output, 0);
            _bc.DoFinal(_output, written);
        }
    }

    private static void WriteNonce(byte[] nonce, long counter)
    {
        Array.Clear(nonce);
        BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(NonceSize - 8), counter);
    }
}
