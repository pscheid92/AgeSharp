using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Age.Benchmarks;

/// <summary>
/// One P-256 exchange as a tagged recipient's Wrap does it — an ephemeral key pair and its
/// ECDH with the recipient's point, from the recipient's encoded point — on the platform's
/// ECDiffieHellman (constant-time, what AgeSharp uses) and on BouncyCastle (the browser's).
/// "Generated" lets the platform draw the key, as recipients do; "Imported" draws the scalar
/// and imports it, as only the known-answer vectors do (slow on macOS).
/// </summary>
[MemoryDiagnoser]
public class P256ExchangeBenchmarks
{
    private static readonly Org.BouncyCastle.Asn1.X9.X9ECParameters Curve = CustomNamedCurves.GetByName("secp256r1");
    private static readonly FixedPointCombMultiplier GeneratorMultiplier = new();
    private readonly SecureRandom _random = new();
    private byte[] _recipientPoint = null!;

    [GlobalSetup]
    public void Setup()
    {
        using var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var q = recipient.ExportParameters(includePrivateParameters: false).Q;
        _recipientPoint = [0x04, .. q.X!, .. q.Y!];

        // Both give the same shared x for the same scalar, and the platform takes a bare scalar.
        var scalar = new byte[32];
        scalar[31] = 7;
        var bc = Curve.Curve.DecodePoint(_recipientPoint).Multiply(new BcBigInteger(1, scalar)).Normalize().AffineXCoord.GetEncoded();
        using var ephemeral = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = scalar });
        using var recipientKey = RecipientKey();
        var platform = ephemeral.DeriveRawSecretAgreement(recipientKey.PublicKey);

        if (!bc.AsSpan().SequenceEqual(platform))
            throw new InvalidOperationException("BouncyCastle and the platform disagree on the shared secret");

        Console.WriteLine($"// P-256 check passed on {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
    }

    [Benchmark(Baseline = true)]
    public byte[] BouncyCastle()
    {
        var recipient = Curve.Curve.DecodePoint(_recipientPoint);
        var bytes = new byte[32];
        _random.NextBytes(bytes);
        var scalar = new BcBigInteger(1, bytes);

        var shared = recipient.Multiply(scalar).Normalize();
        var ephemeral = GeneratorMultiplier.Multiply(Curve.G, scalar).Normalize().GetEncoded(compressed: false);
        return [.. shared.AffineXCoord.GetEncoded(), .. ephemeral];
    }

    [Benchmark]
    public byte[] PlatformGenerated()
    {
        using var recipient = RecipientKey();
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return Exchange(ephemeral, recipient);
    }

    [Benchmark]
    public byte[] PlatformImported()
    {
        using var recipient = RecipientKey();
        var scalar = new byte[32];
        RandomNumberGenerator.Fill(scalar);
        using var ephemeral = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = scalar });
        return Exchange(ephemeral, recipient);
    }

    private static byte[] Exchange(ECDiffieHellman ephemeral, ECDiffieHellman recipient)
    {
        var shared = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);
        var q = ephemeral.ExportParameters(includePrivateParameters: false).Q;
        return [.. shared, 0x04, .. q.X!, .. q.Y!];
    }

    private ECDiffieHellman RecipientKey() =>
        ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = _recipientPoint[1..33], Y = _recipientPoint[33..] },
        });
}
