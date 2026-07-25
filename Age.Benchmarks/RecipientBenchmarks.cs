using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace AgeSharp.Benchmarks;

[MemoryDiagnoser]
public class RecipientBenchmarks
{
    private readonly byte[] _fileKey = new byte[16];

    private MlKem768X25519Identity _mlKemIdentity = null!;
    private MlKem768X25519Recipient _mlKemRecipient = null!;
    private Stanza _mlKemStanza = null!;

    private Passphrase _passphrase = null!;
    private Stanza _scryptStanza = null!;

    private X25519Identity _x25519Identity = null!;
    private X25519Recipient _x25519Recipient = null!;
    private Stanza _x25519Stanza = null!;

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_fileKey);

        // X25519
        _x25519Identity = X25519Identity.Generate();
        _x25519Recipient = _x25519Identity.Recipient;
        _x25519Stanza = _x25519Recipient.Wrap(_fileKey)[0];

        // ML-KEM-768-X25519
        _mlKemIdentity = MlKem768X25519Identity.Generate();
        _mlKemRecipient = _mlKemIdentity.Recipient;
        _mlKemStanza = _mlKemRecipient.Wrap(_fileKey)[0];

        // scrypt (workFactor: 10 to keep benchmarks fast)
        _passphrase = new Passphrase("benchmark-passphrase", 10);
        _scryptStanza = _passphrase.Wrap(_fileKey)[0];
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _x25519Identity.Dispose();
        _mlKemIdentity.Dispose();
    }

    [Benchmark]
    public Stanza X25519Wrap()
    {
        return _x25519Recipient.Wrap(_fileKey)[0];
    }

    [Benchmark]
    public byte[]? X25519Unwrap()
    {
        return _x25519Identity.Unwrap(_x25519Stanza);
    }

    [Benchmark]
    public Stanza MlKem768X25519Wrap()
    {
        return _mlKemRecipient.Wrap(_fileKey)[0];
    }

    [Benchmark]
    public byte[]? MlKem768X25519Unwrap()
    {
        return _mlKemIdentity.Unwrap(_mlKemStanza);
    }

    [Benchmark]
    public Stanza ScryptWrap()
    {
        return _passphrase.Wrap(_fileKey)[0];
    }

    [Benchmark]
    public byte[]? ScryptUnwrap()
    {
        return _passphrase.Unwrap(_scryptStanza);
    }
}