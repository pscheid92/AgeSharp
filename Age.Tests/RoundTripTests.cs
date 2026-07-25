using Xunit;

namespace AgeSharp.Tests;

public class RoundTripTests
{
    [Fact]
    public void X25519_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = "Hello, age!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_RoundTrip_Empty()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = Array.Empty<byte>();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_RoundTrip_Large()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        // Test with data larger than one chunk (> 64 KiB)
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_RoundTrip_ExactChunkSize()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        // Exactly 64 KiB
        var plaintext = new byte[64 * 1024];
        new Random(42).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void Scrypt_RoundTrip()
    {
        var passphrase = "correct horse battery staple";
        var recipient = new Passphrase(passphrase, 10);

        var plaintext = "Hello, scrypt age!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, recipient);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void X25519_MultipleRecipients()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();

        var plaintext = "multi-recipient test"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, id1.Recipient, id2.Recipient);

        // Decrypt with first identity
        encOutput.Position = 0;
        using var decOutput1 = new MemoryStream();
        Age.Decrypt(encOutput, decOutput1, id1);
        Assert.Equal(plaintext, decOutput1.ToArray());

        // Decrypt with second identity
        encOutput.Position = 0;
        using var decOutput2 = new MemoryStream();
        Age.Decrypt(encOutput, decOutput2, id2);
        Assert.Equal(plaintext, decOutput2.ToArray());
    }

    [Fact]
    public void X25519_KeyRoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var identityStr = identity.ToSecretString();
        var recipientStr = identity.Recipient.ToString();

        using var parsed = X25519Identity.Parse(identityStr);
        var parsedRecipient = X25519Recipient.Parse(recipientStr);

        Assert.Equal(identityStr, parsed.ToSecretString());
        Assert.Equal(recipientStr, parsedRecipient.ToString());
    }
}