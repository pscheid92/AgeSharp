using Org.BouncyCastle.Security;
using AgeSharp.Crypto;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// I2 / C9 — an ML-KEM-768-X25519 recipient string is 1216 bytes of bech32, and <c>Parse</c>
/// used to check only the HRP, the length and the case. A structurally invalid encapsulation key
/// was accepted, so a recipients-file validator passed a file that then failed partway through an
/// encryption. Go's <c>ParseHybridRecipient</c> runs the ByteEncode/ByteDecode round trip at parse
/// time; <see cref="XWing.ValidatePublicKey"/> now does the same.
/// </summary>
public class PostQuantumValidationTests
{
    // 1152 bytes of 0xFF cannot be a valid ML-KEM-768 encapsulation key: the coefficients exceed
    // the modulus, so ByteDecode rejects it.
    private static byte[] MalformedPublicKey()
    {
        var key = new byte[XWing.PublicKeySize];
        Array.Fill(key, (byte)0xFF);
        return key;
    }

    [Fact]
    public void Parse_RejectsAStructurallyInvalidEncapsulationKey()
    {
        var recipientString = Bech32.Encode("age1pq", MalformedPublicKey());

        var ex = Assert.Throws<FormatException>(() => MlKem768X25519Recipient.Parse(recipientString));

        Assert.Contains("ML-KEM-768", ex.Message, StringComparison.Ordinal);
    }

    // FIPS 203 requires every coefficient of an encapsulation key below q = 3329. BouncyCastle
    // checks that when decoding since 2.7.0; this pins it, at the boundary, for every hybrid.
    [Theory]
    [InlineData(3328, false)]
    [InlineData(3329, true)]
    [InlineData(4095, true)]
    public void ACoefficientOfQOrMore_IsRefusedWhenDecoded(int coefficient, bool refused)
    {
        using var identity = MlKem768X25519Identity.Generate();
        var (_, key) = Bech32.Decode(identity.Recipient.ToString());
        key[0] = (byte)coefficient;
        key[1] = (byte)((key[1] & 0xF0) | (coefficient >> 8));

        var ex = Record.Exception(() => MlKem768EncapsulationKey.Decode(key.AsSpan(0, MlKem768EncapsulationKey.Size)));

        if (refused)
            Assert.Contains("a coefficient is not less than the modulus", Assert.IsType<FormatException>(ex).Message);
        else
            Assert.Null(ex);
    }

    [Theory]
    [InlineData(MlKem768EncapsulationKey.Size - 1)]
    [InlineData(MlKem768EncapsulationKey.Size + 1)]
    public void AnEncapsulationKeyOfTheWrongLength_IsRefusedWhenDecoded(int length)
    {
        var ex = Assert.Throws<FormatException>(() => MlKem768EncapsulationKey.Decode(new byte[length]));

        Assert.Contains($"must be {MlKem768EncapsulationKey.Size} bytes", ex.Message);
    }

    [Fact]
    public void Parse_StillAcceptsAGenuineRecipient()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = identity.Recipient.ToString();

        Assert.Equal(text, MlKem768X25519Recipient.Parse(text).ToString());
    }

    [Fact]
    public void ValidatePublicKey_RejectsTheWrongLength()
    {
        var ex = Assert.Throws<FormatException>(() => XWing.ValidatePublicKey(new byte[10]));

        Assert.Contains($"{XWing.PublicKeySize} bytes", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidatePublicKey_AcceptsAGenuineKey()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var (_, data) = Bech32.Decode(identity.Recipient.ToString());

        XWing.ValidatePublicKey(data); // must not throw
    }

    // Encapsulate is internal and reachable without going through Parse, so it keeps its own guard —
    // C9's point was that Decapsulate guarded its inputs and Encapsulate did not.
    [Fact]
    public void Encapsulate_OnAMalformedKey_IsAnAgeExceptionNotABclOne()
    {
        var ex = Record.Exception(() => XWing.Encapsulate(MalformedPublicKey(), new SecureRandom()));

        Assert.NotNull(ex);
        Assert.IsAssignableFrom<AgeException>(ex);
        Assert.Contains("ML-KEM-768", ex.Message, StringComparison.Ordinal);
    }

    // Through the public API this is now unreachable — Parse rejects such a recipient first —
    // which is exactly the belt-and-braces the two fixes together provide.
    [Fact]
    public void EncryptingToAMalformedRecipient_FailsAtParseNotMidEncryption()
    {
        var recipientString = Bech32.Encode("age1pq", MalformedPublicKey());

        Assert.Throws<FormatException>(() => MlKem768X25519Recipient.Parse(recipientString));
    }
}
