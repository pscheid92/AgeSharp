using Age;
using Age.Recipients;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

// A 256 MiB file through every encrypt and decrypt path, written to Stream.Null: at this size an
// output MemoryStream's growth would dominate both time and allocation, so the numbers here are
// the pipeline alone. Allocation should not grow with the file (the README promises bounded
// memory). Few iterations, because each one moves a quarter of a gigabyte or more.
[MemoryDiagnoser]
[SimpleJob(warmupCount: 1, iterationCount: 5)]
public class LargeFileBenchmarks
{
    private const int FileSize = 256 * 1024 * 1024;

    private X25519Identity _identity = null!;
    private X25519Recipient _recipient = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;
    private byte[] _armoredCiphertext = null!;

    [GlobalSetup]
    public void Setup()
    {
        _identity = X25519Identity.Generate();
        _recipient = _identity.Recipient;

        _plaintext = new byte[FileSize];
        Random.Shared.NextBytes(_plaintext);

        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(_plaintext), encrypted, _recipient);
        _ciphertext = encrypted.ToArray();

        using var armored = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(_plaintext), armored, armor: true, _recipient);
        _armoredCiphertext = armored.ToArray();
    }

    [GlobalCleanup]
    public void Cleanup() => _identity.Dispose();

    [Benchmark]
    public void Encrypt256MiB() =>
        AgeEncrypt.Encrypt(new MemoryStream(_plaintext), Stream.Null, _recipient);

    [Benchmark]
    public void Decrypt256MiB() =>
        AgeEncrypt.Decrypt(new MemoryStream(_ciphertext), Stream.Null, _identity);

    [Benchmark]
    public void EncryptArmored256MiB() =>
        AgeEncrypt.Encrypt(new MemoryStream(_plaintext), Stream.Null, armor: true, _recipient);

    [Benchmark]
    public void DecryptArmored256MiB() =>
        AgeEncrypt.Decrypt(new MemoryStream(_armoredCiphertext), Stream.Null, _identity);
}
