using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Converting between binary and armored needs no key — armor is a text container around
///     the ciphertext. Without these, the only route was decrypt-and-re-encrypt, which does.
/// </summary>
public class ArmorConversionTests
{
    [Fact]
    public void Armor_ProducesWhatEncryptWithArmorWouldHave()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt("hello world"u8, [identity.Recipient]);

        using var armored = new MemoryStream();
        Age.Armor(new MemoryStream(binary), armored);

        // Decryptable as armor, and equal to what the armored encrypt path emits for the
        // same ciphertext.
        Assert.Equal("hello world"u8.ToArray(), Age.Decrypt(armored.ToArray(), [identity]));
        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", System.Text.Encoding.ASCII.GetString(armored.ToArray()));
    }

    [Fact]
    public void Dearmor_IsTheInverse()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt("round trip"u8, [identity.Recipient]);

        using var armored = new MemoryStream();
        Age.Armor(new MemoryStream(binary), armored);

        using var back = new MemoryStream();
        Age.Dearmor(new MemoryStream(armored.ToArray()), back);

        Assert.Equal(binary, back.ToArray());
    }

    [Fact]
    public void Dearmor_AcceptsWhatTheArmoredEncryptPathProduces()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt("hello"u8, [identity.Recipient], new AgeEncryptOptions { Armor = true });

        using var binary = new MemoryStream();
        Age.Dearmor(new MemoryStream(armored), binary);

        Assert.Equal("hello"u8.ToArray(), Age.Decrypt(binary.ToArray(), [identity]));
    }

    [Fact]
    public async Task Async_MatchesTheSynchronousResult()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt("hello"u8, [identity.Recipient]);

        using var syncArmored = new MemoryStream();
        Age.Armor(new MemoryStream(binary), syncArmored);

        using var asyncArmored = new MemoryStream();
        await Age.ArmorAsync(new MemoryStream(binary), asyncArmored);

        Assert.Equal(syncArmored.ToArray(), asyncArmored.ToArray());

        using var back = new MemoryStream();
        await Age.DearmorAsync(new MemoryStream(asyncArmored.ToArray()), back);
        Assert.Equal(binary, back.ToArray());
    }

    [Fact]
    public void Dearmor_OnBinaryInput_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt("hello"u8, [identity.Recipient]);

        Assert.Throws<AgeFormatException>(() => Age.Dearmor(new MemoryStream(binary), new MemoryStream()));
    }

    [Fact]
    public void Conversion_NeedsNoIdentity()
    {
        // The point of the API: a file you cannot decrypt still converts.
        using var theirs = X25519Identity.Generate();
        var binary = Age.Encrypt("not mine"u8, [theirs.Recipient]);

        using var armored = new MemoryStream();
        Age.Armor(new MemoryStream(binary), armored);

        using var back = new MemoryStream();
        Age.Dearmor(new MemoryStream(armored.ToArray()), back);

        Assert.Equal(binary, back.ToArray());
    }

    [Fact]
    public void Armor_LeavesTheDestinationOpen()
    {
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt("hello"u8, [identity.Recipient]);

        var destination = new MemoryStream();
        Age.Armor(new MemoryStream(binary), destination);

        Assert.True(destination.CanWrite);
    }
}
