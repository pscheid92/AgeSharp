using BenchmarkDotNet.Attributes;

namespace AgeSharp.Benchmarks;

/// <summary>
///     Measures the overhead of the async facades relative to their synchronous
///     counterparts over in-memory streams (so the numbers isolate the state-machine
///     and header-prefill cost, not disk/network latency).
/// </summary>
[MemoryDiagnoser]
public class AsyncBenchmarks
{
    [Params(65_536, 1_048_576)] public int DataSize;

    private byte[] _ciphertext = null!;
    private IReadOnlyList<IIdentity> _identities = null!;

    private X25519Identity _identity = null!;
    private byte[] _plaintext = null!;
    private IReadOnlyList<IRecipient> _recipients = null!;

    [GlobalSetup]
    public void Setup()
    {
        _identity = X25519Identity.Generate();
        _recipients = [_identity.Recipient];
        _identities = [_identity];

        _plaintext = new byte[DataSize];
        Random.Shared.NextBytes(_plaintext);

        using var encOut = new MemoryStream();
        Age.Encrypt(new MemoryStream(_plaintext), encOut, _identity.Recipient);
        _ciphertext = encOut.ToArray();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _identity.Dispose();
    }

    [Benchmark]
    public void EncryptSync()
    {
        using var input = new MemoryStream(_plaintext);
        using var output = new MemoryStream();
        Age.Encrypt(input, output, _identity.Recipient);
    }

    [Benchmark]
    public async Task EncryptAsync()
    {
        using var input = new MemoryStream(_plaintext);
        using var output = new MemoryStream();
        await Age.EncryptAsync(input, output, _recipients);
    }

    [Benchmark]
    public void DecryptSync()
    {
        using var input = new MemoryStream(_ciphertext);
        using var output = new MemoryStream();
        Age.Decrypt(input, output, _identity);
    }

    [Benchmark]
    public async Task DecryptAsync()
    {
        using var input = new MemoryStream(_ciphertext);
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, _identities);
    }
}