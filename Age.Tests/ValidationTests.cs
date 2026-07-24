using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Argument and invariant validation on the public entry points: the encrypt-side
/// scrypt-must-be-alone rule, empty identity lists, and <see cref="Stanza"/>
/// constructor input validation.
/// </summary>
public class ValidationTests
{
    private const int LowWorkFactor = 10;

    private static MemoryStream Plaintext() => new("hello"u8.ToArray());

    private static MemoryStream EncryptTo(IRecipient recipient)
    {
        var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(Plaintext(), encrypted, recipient);
        encrypted.Position = 0;
        return encrypted;
    }

    // --- scrypt recipients must stand alone (mirror of the decrypt-side rule) ---

    [Fact]
    public void Encrypt_ScryptMixedWithX25519_Throws()
    {
        using var identity = X25519Identity.Generate();
        var scrypt = new ScryptRecipient("pw", LowWorkFactor);

        var ex = Assert.Throws<AgeException>(() =>
            AgeEncrypt.Encrypt(Plaintext(), new MemoryStream(), scrypt, identity.Recipient));

        Assert.Contains("only recipient", ex.Message);
    }

    [Fact]
    public void Encrypt_TwoScryptRecipients_Throws()
    {
        var first = new ScryptRecipient("pw1", LowWorkFactor);
        var second = new ScryptRecipient("pw2", LowWorkFactor);

        Assert.Throws<AgeException>(() =>
            AgeEncrypt.Encrypt(Plaintext(), new MemoryStream(), first, second));
    }

    [Fact]
    public void EncryptDetached_ScryptMixedWithX25519_Throws()
    {
        using var identity = X25519Identity.Generate();
        var scrypt = new ScryptRecipient("pw", LowWorkFactor);

        Assert.Throws<AgeException>(() =>
            AgeEncrypt.EncryptDetached(Plaintext(), new MemoryStream(), new MemoryStream(), scrypt, identity.Recipient));
    }

    [Fact]
    public void EncryptReader_ScryptMixedWithX25519_Throws()
    {
        using var identity = X25519Identity.Generate();
        var scrypt = new ScryptRecipient("pw", LowWorkFactor);

        Assert.Throws<AgeException>(() =>
            AgeEncrypt.EncryptReader(Plaintext(), scrypt, identity.Recipient));
    }

    [Fact]
    public void Encrypt_ScryptAlone_StillRoundTrips()
    {
        var scrypt = new ScryptRecipient("pw", LowWorkFactor);
        using var encrypted = EncryptTo(scrypt);

        using var decrypted = new MemoryStream();
        AgeEncrypt.Decrypt(encrypted, decrypted, scrypt);

        Assert.Equal("hello"u8.ToArray(), decrypted.ToArray());
    }

    // --- empty identity lists are a caller bug, not "no match" ---

    [Fact]
    public void Decrypt_NoIdentities_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();
        using var encrypted = EncryptTo(identity.Recipient);

        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.Decrypt(encrypted, new MemoryStream()));

        Assert.Equal("identities", ex.ParamName);
    }

    [Fact]
    public void DecryptReader_NoIdentities_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();
        using var encrypted = EncryptTo(identity.Recipient);

        Assert.Throws<ArgumentException>(() => AgeEncrypt.DecryptReader(encrypted));
    }

    [Fact]
    public void DecryptDetached_NoIdentities_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.DecryptDetached(new MemoryStream(), new MemoryStream(), new MemoryStream()));
    }

    [Fact]
    public void RandomAccess_NoIdentities_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();
        using var encrypted = EncryptTo(identity.Recipient);

        Assert.Throws<ArgumentException>(() => new AgeRandomAccess(encrypted));
    }

    // --- Stanza constructor rejects input that would corrupt header framing ---

    [Fact]
    public void Stanza_Ctor_ValidInput_IsPreserved()
    {
        var stanza = new Stanza("X25519", ["argA", "argB"], [1, 2, 3]);

        Assert.Equal("X25519", stanza.Type);
        Assert.Equal(["argA", "argB"], stanza.Args);
        Assert.Equal(new byte[] { 1, 2, 3 }, stanza.Body.ToArray());
    }

    [Theory]
    [InlineData("")]            // empty type is unrepresentable
    [InlineData("my type")]     // space changes argument framing
    [InlineData("my\ntype")]    // newline injects header lines
    [InlineData("tüpe")]   // outside printable ASCII
    public void Stanza_Ctor_InvalidType_ThrowsArgumentException(string type)
    {
        Assert.Throws<ArgumentException>(() => new Stanza(type, [], []));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a b")]
    [InlineData("a\nb")]
    [InlineData("\t")]
    public void Stanza_Ctor_InvalidArg_ThrowsArgumentException(string arg)
    {
        Assert.Throws<ArgumentException>(() => new Stanza("type", [arg], []));
    }

    [Fact]
    public void Stanza_Ctor_NullInputs_ThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new Stanza(null!, [], []));
        Assert.Throws<ArgumentNullException>(() => new Stanza("type", null!, []));
        Assert.Throws<ArgumentNullException>(() => new Stanza("type", [], null!));
    }
}
