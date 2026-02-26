using Age;
using Age.Recipients;
using BenchmarkDotNet.Attributes;

namespace Age.Benchmarks;

[MemoryDiagnoser]
public class EncryptDecryptBenchmarks
{
    [Params(1024, 65_536, 1_048_576)]
    public int DataSize;

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

        _plaintext = new byte[DataSize];
        Random.Shared.NextBytes(_plaintext);

        // Pre-encrypt for decrypt benchmarks
        using var encOut = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(_plaintext), encOut, _recipient);
        _ciphertext = encOut.ToArray();

        using var armorOut = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(_plaintext), armorOut, armor: true, _recipient);
        _armoredCiphertext = armorOut.ToArray();
    }

    [GlobalCleanup]
    public void Cleanup() => _identity.Dispose();

    [Benchmark]
    public void Encrypt()
    {
        using var input = new MemoryStream(_plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, _recipient);
    }

    [Benchmark]
    public void Decrypt()
    {
        using var input = new MemoryStream(_ciphertext);
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(input, output, _identity);
    }

    [Benchmark]
    public void EncryptArmored()
    {
        using var input = new MemoryStream(_plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, armor: true, _recipient);
    }

    [Benchmark]
    public void DecryptArmored()
    {
        using var input = new MemoryStream(_armoredCiphertext);
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(input, output, _identity);
    }
}
