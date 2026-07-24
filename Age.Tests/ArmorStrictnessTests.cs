using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// <see cref="AgeOptions.Armor"/> means the same thing in both directions — this
/// file is armored — but on decryption it is a strictness opt-in rather than a
/// switch, since armor is auto-detected regardless.
/// </summary>
public class ArmorStrictnessTests
{
    private static readonly byte[] Plaintext = "strictness"u8.ToArray();

    private static AgeOptions Required => new() { Armor = true };

    [Fact]
    public void RequiringArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, Required, identity.Recipient);

        Assert.Equal(Plaintext, Age.Decrypt(armored, Required, identity));
    }

    [Fact]
    public void RequiringArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        var ex = Assert.Throws<AgeFormatException>(() => Age.Decrypt(binary, Required, identity));
        Assert.Contains("not ASCII-armored", ex.Message);
    }

    [Fact]
    public void NotRequiringArmor_StillAcceptsBoth()
    {
        // The default must stay permissive: detection decides, not the flag.
        using var identity = X25519Identity.Generate();

        Assert.Equal(Plaintext, Age.Decrypt(Age.Encrypt(Plaintext, identity.Recipient), identity));
        Assert.Equal(Plaintext, Age.Decrypt(Age.Encrypt(Plaintext, Required, identity.Recipient), identity));
    }

    [Fact]
    public void OpenRead_RequiringArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        Assert.Throws<AgeFormatException>(() =>
            Age.OpenRead(new MemoryStream(binary), Required, identity));
    }

    [Fact]
    public async Task DecryptAsync_RequiringArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        using var input = new MemoryStream(binary);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<AgeFormatException>(async () =>
            await Age.DecryptAsync(input, output, [identity], Required));
    }

    [Fact]
    public async Task DecryptAsync_RequiringArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, Required, identity.Recipient);

        using var input = new MemoryStream(armored);
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity], Required);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void ReadHeader_RequiringArmor_RejectsBinaryInput()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        Assert.Throws<AgeFormatException>(() => Age.ReadHeader(new MemoryStream(binary), Required));
    }

    [Fact]
    public void ReadHeader_RequiringArmor_AcceptsArmoredInput()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, Required, identity.Recipient);

        var header = Age.ReadHeader(new MemoryStream(armored), Required);

        Assert.True(header.IsArmored);
    }

    [Fact]
    public void RequiringArmor_WorksOverANonSeekableStream()
    {
        // Strictness rides on the same lookahead detection, so it must not need seek.
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(binary));
        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() => Age.Decrypt(input, output, Required, identity));
    }

    [Fact]
    public void OneOptionsObject_CanBeSharedByBothDirections()
    {
        // The point of keeping a single options type: a caller with one config object
        // uses it for encrypt and decrypt alike.
        using var identity = X25519Identity.Generate();
        var options = new AgeOptions { Armor = true, MaxHeaderBytes = 512 * 1024 };

        var ciphertext = Age.Encrypt(Plaintext, options, identity.Recipient);

        Assert.Equal(Plaintext, Age.Decrypt(ciphertext, options, identity));
    }
}
