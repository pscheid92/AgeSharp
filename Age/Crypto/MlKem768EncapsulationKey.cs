using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Age.Crypto;

/// <summary>
/// An ML-KEM-768 encapsulation key (FIPS 203), checked when it is decoded: the post-quantum half
/// of both hybrid KEMs, X-Wing and MLKEM768-P256.
/// </summary>
internal sealed class MlKem768EncapsulationKey
{
    /// <summary>The encoded size: 3 polynomials of 256 coefficients at 12 bits, then a 32-byte seed.</summary>
    internal const int Size = 1184;

    /// <summary>The ciphertext size.</summary>
    internal const int CiphertextSize = 1088;

    private const int SharedSecretSize = 32;

    private readonly MLKemPublicKeyParameters _key;

    private MlKem768EncapsulationKey(MLKemPublicKeyParameters key) =>
        _key = key;

    /// <summary>Decodes an encapsulation key.</summary>
    /// <exception cref="FormatException">
    /// It is not <see cref="Size"/> bytes, or a coefficient is not below the modulus, as FIPS 203's
    /// encapsulation-key check requires. BouncyCastle makes that check when decoding (since 2.7.0;
    /// earlier versions left it to the first encapsulation), and the tests that parse keys with an
    /// out-of-range coefficient hold it to that.
    /// </exception>
    public static MlKem768EncapsulationKey Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != Size)
            throw new FormatException($"invalid ML-KEM-768 encapsulation key: must be {Size} bytes, got {encoded.Length}");

        try
        {
            return new MlKem768EncapsulationKey(MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, encoded.ToArray()));
        }
        catch (ArgumentException ex) when (ex.Message.StartsWith("Modulus check failed", StringComparison.Ordinal))
        {
            throw new FormatException("invalid ML-KEM-768 encapsulation key: a coefficient is not less than the modulus", ex);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw new FormatException($"invalid ML-KEM-768 encapsulation key: {ex.Message}", ex);
        }
    }

    /// <summary>Encapsulates: the ciphertext and the shared secret, with randomness from <paramref name="random"/>.</summary>
    public (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(SecureRandom random)
    {
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(_key, random));

        var ciphertext = new byte[CiphertextSize];
        var sharedSecret = new byte[SharedSecretSize];

        try
        {
            encapsulator.Encapsulate(ciphertext, 0, CiphertextSize, sharedSecret, 0, SharedSecretSize);
            return (ciphertext, sharedSecret);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw;
        }
    }
}
