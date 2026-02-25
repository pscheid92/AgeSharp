using System.Security.Cryptography;
using Age.Format;
using Age.Recipients;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

[MemoryDiagnoser]
public class RecipientBenchmarks
{
    private readonly byte[] _fileKey = new byte[16];

    private X25519Identity _x25519Identity = null!;
    private X25519Recipient _x25519Recipient = null!;
    private Stanza _x25519Stanza = null!;

    private MlKem768X25519Identity _mlKemIdentity = null!;
    private MlKem768X25519Recipient _mlKemRecipient = null!;
    private Stanza _mlKemStanza = null!;

    private ScryptRecipient _scryptRecipient = null!;
    private Stanza _scryptStanza = null!;

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_fileKey);

        // X25519
        _x25519Identity = X25519Identity.Generate();
        _x25519Recipient = _x25519Identity.Recipient;
        _x25519Stanza = _x25519Recipient.Wrap(_fileKey);

        // ML-KEM-768-X25519
        _mlKemIdentity = MlKem768X25519Identity.Generate();
        _mlKemRecipient = _mlKemIdentity.Recipient;
        _mlKemStanza = _mlKemRecipient.Wrap(_fileKey);

        // scrypt (workFactor: 10 to keep benchmarks fast)
        _scryptRecipient = new ScryptRecipient("benchmark-passphrase", workFactor: 10);
        _scryptStanza = _scryptRecipient.Wrap(_fileKey);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _x25519Identity.Dispose();
        _mlKemIdentity.Dispose();
    }

    [Benchmark]
    public Stanza X25519Wrap() => _x25519Recipient.Wrap(_fileKey);

    [Benchmark]
    public byte[]? X25519Unwrap() => _x25519Identity.Unwrap(_x25519Stanza);

    [Benchmark]
    public Stanza MlKem768X25519Wrap() => _mlKemRecipient.Wrap(_fileKey);

    [Benchmark]
    public byte[]? MlKem768X25519Unwrap() => _mlKemIdentity.Unwrap(_mlKemStanza);

    [Benchmark]
    public Stanza ScryptWrap() => _scryptRecipient.Wrap(_fileKey);

    [Benchmark]
    public byte[]? ScryptUnwrap() => ((IIdentity)_scryptRecipient).Unwrap(_scryptStanza);
}
