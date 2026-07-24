using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// <see cref="AgeDecryptOptions.RequireArmor"/> is a strictness opt-in, not a
/// switch: armor is detected automatically either way, so the default accepts both
/// forms and setting it rejects anything that is not armored.
/// </summary>
public class ArmorStrictnessTests
{
    private static readonly byte[] Plaintext = "strictness"u8.ToArray();

    private static AgeDecryptOptions Required => new() { RequireArmor = true };
    private static AgeEncryptOptions Armored => new() { Armor = true };

    [Fact]
    public void RequireArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, Armored, identity.Recipient);

        Assert.Equal(Plaintext, Age.Decrypt(armored, Required, identity));
    }

    [Fact]
    public void RequireArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        var ex = Assert.Throws<AgeFormatException>(() => Age.Decrypt(binary, Required, identity));
        Assert.Contains("not ASCII-armored", ex.Message);
    }

    [Fact]
    public void TheDefault_StillAcceptsBothForms()
    {
        using var identity = X25519Identity.Generate();

        Assert.Equal(Plaintext, Age.Decrypt(Age.Encrypt(Plaintext, identity.Recipient), identity));
        Assert.Equal(Plaintext, Age.Decrypt(Age.Encrypt(Plaintext, Armored, identity.Recipient), identity));
    }

    [Fact]
    public void OpenRead_RequireArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        Assert.Throws<AgeFormatException>(() => Age.OpenRead(new MemoryStream(binary), Required, identity));
    }

    [Fact]
    public async Task DecryptAsync_RequireArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        using var input = new MemoryStream(binary);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<AgeFormatException>(async () =>
            await Age.DecryptAsync(input, output, [identity], Required));
    }

    [Fact]
    public async Task DecryptAsync_RequireArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, Armored, identity.Recipient);

        using var input = new MemoryStream(armored);
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity], Required);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void ReadHeader_RequireArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        Assert.Throws<AgeFormatException>(() => Age.ReadHeader(new MemoryStream(binary), Required));
    }

    [Fact]
    public void RequireArmor_WorksOverANonSeekableStream()
    {
        // Strictness rides on the same lookahead detection, so it must not need seek.
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(binary));
        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() => Age.Decrypt(input, output, Required, identity));
    }

    // --- the split itself ---

    [Fact]
    public void EachOptionsType_ExposesOnlyMembersThatApplyToIt()
    {
        // The point of two types: no member is inert where it is accepted. This guards
        // against a parsing knob drifting onto the encrypt side, or vice versa.
        Assert.Equal(
            ["Armor"],
            typeof(AgeEncryptOptions).GetProperties().Select(p => p.Name).Order());

        Assert.Equal(
            ["MaxArmorLineBytes", "MaxHeaderBytes", "MaxHeaderLineBytes", "RequireArmor"],
            typeof(AgeDecryptOptions).GetProperties().Select(p => p.Name).Order());
    }
}
