using System.Text;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Tests for the buffer-in, buffer-out one-shot overloads
///     <see cref="Age.Encrypt(System.ReadOnlySpan{byte}, System.ReadOnlySpan{IRecipient})" /> and
///     <see cref="Age.Decrypt(System.ReadOnlySpan{byte}, System.ReadOnlySpan{IIdentity})" />:
///     round-trip across sizes, the armor option, validation, and an age-CLI interop vector.
/// </summary>
public class ByteArrayOverloadTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(65536)] // exact chunk
    [InlineData(131073)] // multi-chunk + tail
    public void Encrypt_Decrypt_RoundTrip(int size)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[size];
        if (size > 0) new Random(42).NextBytes(plaintext);

        var ciphertext = Age.Encrypt(plaintext, identity.Recipient);
        var result = Age.Decrypt(ciphertext, identity);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public void Encrypt_Armored_ProducesArmor_AndRoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "armored buffer payload"u8.ToArray();

        var ciphertext = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", Encoding.ASCII.GetString(ciphertext));
        // Decrypt auto-detects armor from the seekable buffer.
        Assert.Equal(plaintext, Age.Decrypt(ciphertext, identity));
    }

    [Fact]
    public void Encrypt_MultipleRecipients_EachIdentityDecrypts()
    {
        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        var plaintext = "shared buffer"u8.ToArray();

        var ciphertext = Age.Encrypt(plaintext, a.Recipient, b.Recipient);

        Assert.Equal(plaintext, Age.Decrypt(ciphertext, a));
        Assert.Equal(plaintext, Age.Decrypt(ciphertext, b));
    }

    [Fact]
    public void Encrypt_NoRecipients_Throws()
    {
        Assert.Throws<ArgumentException>(() => Age.Encrypt("x"u8.ToArray(), Array.Empty<IRecipient>()));
    }

    [Fact]
    public void Decrypt_NoIdentities_Throws()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Age.Encrypt("x"u8.ToArray(), identity.Recipient);

        Assert.Throws<ArgumentException>(() => Age.Decrypt(ciphertext, Array.Empty<IIdentity>()));
    }

    [Fact]
    public void Decrypt_WrongIdentity_Throws()
    {
        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        var ciphertext = Age.Encrypt("secret"u8.ToArray(), a.Recipient);

        Assert.Throws<NoIdentityMatchException>(() => Age.Decrypt(ciphertext, b));
    }

    [Fact]
    public void Encrypt_MixedPqAndClassicRecipients_Rejected()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();

        Assert.Throws<AgeException>(() => Age.Encrypt("x"u8.ToArray(), x25519.Recipient, pq.Recipient));
    }

    // --- Interop: buffer overloads cross-check against the reference age CLI ---

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void Encrypt_Buffer_DecryptWithAge(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = new byte[4096];
        new Random(7).NextBytes(plaintext);

        var ciphertext = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = armored }, identity.Recipient);

        Assert.Equal(plaintext, AgeCli.Decrypt(identity.ToSecretString(), ciphertext));
    }

    [SkippableFact]
    public void EncryptWithAge_Decrypt_Buffer()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = new byte[4096];
        new Random(7).NextBytes(plaintext);

        var ciphertext = AgeCli.Encrypt(plaintext, false, identity.Recipient.ToString());

        Assert.Equal(plaintext, Age.Decrypt(ciphertext, identity));
    }
}