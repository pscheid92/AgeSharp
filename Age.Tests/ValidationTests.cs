using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

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
        Age.Encrypt(Plaintext(), encrypted, recipient);
        encrypted.Position = 0;
        return encrypted;
    }

    // --- scrypt recipients must stand alone (mirror of the decrypt-side rule) ---

    [Fact]
    public void Encrypt_ScryptMixedWithX25519_Throws()
    {
        using var identity = X25519Identity.Generate();
        var passphrase = new Passphrase("pw", LowWorkFactor);

        var ex = Assert.Throws<AgeException>(() =>
            Age.Encrypt(Plaintext(), new MemoryStream(), passphrase, identity.Recipient));

        Assert.Contains("only recipient", ex.Message);
    }

    [Fact]
    public void Encrypt_TwoPassphrases_Throws()
    {
        var first = new Passphrase("pw1", LowWorkFactor);
        var second = new Passphrase("pw2", LowWorkFactor);

        Assert.Throws<AgeException>(() =>
            Age.Encrypt(Plaintext(), new MemoryStream(), first, second));
    }

    [Fact]
    public void EncryptDetached_ScryptMixedWithX25519_Throws()
    {
        using var identity = X25519Identity.Generate();
        var passphrase = new Passphrase("pw", LowWorkFactor);

        Assert.Throws<AgeException>(() =>
            Age.EncryptDetached(Plaintext(), new MemoryStream(), new MemoryStream(), passphrase, identity.Recipient));
    }

    [Fact]
    public void EncryptReader_ScryptMixedWithX25519_Throws()
    {
        using var identity = X25519Identity.Generate();
        var passphrase = new Passphrase("pw", LowWorkFactor);

        Assert.Throws<AgeException>(() =>
            Age.EncryptReader(Plaintext(), passphrase, identity.Recipient));
    }

    [Fact]
    public void Encrypt_ScryptAlone_StillRoundTrips()
    {
        var passphrase = new Passphrase("pw", LowWorkFactor);
        using var encrypted = EncryptTo(passphrase);

        using var decrypted = new MemoryStream();
        Age.Decrypt(encrypted, decrypted, passphrase);

        Assert.Equal("hello"u8.ToArray(), decrypted.ToArray());
    }

    // --- empty collections are a caller bug, not "no match" ---
    //
    // Omitting recipients/identities *entirely* no longer reaches these guards: the
    // `first, params rest` overloads make that a compile error. What survives is the
    // collection overload, where emptiness is only knowable at runtime — so these
    // tests now pin the one shape that still needs a guard.

    private static readonly IIdentity[] NoIdentities = [];
    private static readonly IRecipient[] NoRecipients = [];

    [Fact]
    public void Decrypt_NoIdentities_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();
        using var encrypted = EncryptTo(identity.Recipient);

        var ex = Assert.Throws<ArgumentException>(() =>
            Age.Decrypt(encrypted, new MemoryStream(), NoIdentities));

        Assert.Equal("identities", ex.ParamName);
    }

    [Fact]
    public void DecryptReader_NoIdentities_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();
        using var encrypted = EncryptTo(identity.Recipient);

        Assert.Throws<ArgumentException>(() => Age.DecryptReader(encrypted, NoIdentities));
    }

    [Fact]
    public void DecryptDetached_NoIdentities_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            Age.DecryptDetached(new MemoryStream(), new MemoryStream(), new MemoryStream(), NoIdentities));
    }

    [Fact]
    public async Task DecryptAsync_NoIdentities_ThrowsArgumentException()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await Age.DecryptAsync(new MemoryStream(), new MemoryStream(), NoIdentities));

        Assert.Equal("identities", ex.ParamName);
    }

    // --- and the same on the encrypt side ---

    [Fact]
    public void EncryptDetached_NoRecipients_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            Age.EncryptDetached(new MemoryStream(), new MemoryStream(), new MemoryStream(), NoRecipients));

        Assert.Equal("recipients", ex.ParamName);
    }

    [Fact]
    public void EncryptReader_NoRecipients_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => Age.EncryptReader(new MemoryStream(), NoRecipients));

        Assert.Equal("recipients", ex.ParamName);
    }

    [Fact]
    public async Task EncryptAsync_NoRecipients_ThrowsArgumentException()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await Age.EncryptAsync(new MemoryStream(), new MemoryStream(), NoRecipients));

        Assert.Equal("recipients", ex.ParamName);
    }

    // --- null is rejected on both shapes ---

    [Fact]
    public void Encrypt_NullFirstRecipient_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Age.Encrypt(Plaintext(), new MemoryStream(), (IRecipient)null!));
    }

    [Fact]
    public void Encrypt_NullRecipientCollection_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            Age.Encrypt(Plaintext(), new MemoryStream(), (IReadOnlyList<IRecipient>)null!));

        Assert.Equal("recipients", ex.ParamName);
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

    // --- a null *inside* the collection ---------------------------------------

    // The collection overloads are the only shape that can carry a null element, and a
    // caller who hits it deserves to be told which slot rather than an NRE thrown from
    // inside the wrap loop.
    [Fact]
    public void Encrypt_NullRecipientInCollection_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();

        var ex = Assert.Throws<ArgumentException>(() =>
            Age.Encrypt("x"u8, new IRecipient[] { identity.Recipient, null! }));

        Assert.Contains("index 1", ex.Message);
    }

    [Fact]
    public void Decrypt_NullIdentityInCollection_ThrowsArgumentException()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt("x"u8, identity.Recipient);

        Assert.Throws<ArgumentException>(() =>
            Age.Decrypt(ciphertext, new IIdentity[] { null!, identity }));
    }

    // --- the parsing limits are caller configuration, not file content ---------

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void DecryptOptions_NonPositiveLimits_ThrowAtConstruction(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxHeaderLineBytes = value });
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxHeaderBytes = value });
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxArmorLineBytes = value });
    }
}
