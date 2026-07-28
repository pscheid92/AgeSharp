using Age.Crypto;
using Age.Recipients;
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

    // Encaps is internal and reachable without going through Parse, so it keeps its own guard —
    // C9's point was that Decaps guarded its inputs and Encaps did not.
    [Fact]
    public void Encaps_OnAMalformedKey_IsAnAgeExceptionNotABclOne()
    {
        var ex = Record.Exception(() => XWing.Encaps(MalformedPublicKey()));

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
