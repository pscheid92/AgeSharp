using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A passphrase encrypts and decrypts as one object, keeps only a copy it can clear, and refuses
/// to decrypt with more work than its <see cref="Passphrase.MaxWorkFactor"/> allows.
/// </summary>
public class PassphraseTests
{
    private static readonly byte[] Plaintext = "under a passphrase"u8.ToArray();

    [Fact]
    public void ThePassphraseFromCharacters_IsCopied_SoTheCallerCanClearThem()
    {
        var characters = "correct horse".ToCharArray();
        using var passphrase = new Passphrase(characters.AsSpan(), 10);
        Array.Clear(characters);

        var file = new Recipients(passphrase).Encrypt(Plaintext);

        using var same = new Passphrase("correct horse");
        Assert.Equal(Plaintext, new Identities(same).Decrypt(file));
    }

    [Fact]
    public void EveryConstructor_Encrypts()
    {
        using var a = new Passphrase("pw");
        using var b = new Passphrase("pw", 10);
        using var c = new Passphrase("pw".AsSpan());
        using var d = new Passphrase("pw".AsSpan(), 10);

        foreach (var passphrase in new[] { b, d })
            Assert.Equal(Plaintext, new Identities(a).Decrypt(new Recipients(passphrase).Encrypt(Plaintext)));

        Assert.Equal(Plaintext, new Identities(b).Decrypt(new Recipients(c).Encrypt(Plaintext)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(23)]
    public void AWorkFactorOtherReadersRefuse_IsRefused(int workFactor)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Passphrase("pw", workFactor));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Passphrase("pw".AsSpan(), workFactor));
    }

    [Fact]
    public void ANullPassphrase_IsRefused()
    {
        Assert.Throws<ArgumentNullException>(() => new Passphrase((string)null!));
        Assert.Throws<ArgumentNullException>(() => new Passphrase((string)null!, 10));
    }

    [Fact]
    public void AFileAskingForMoreThanTheMaximum_IsRefused()
    {
        using var encrypting = new Passphrase("pw", 12);
        var file = new Recipients(encrypting).Encrypt(Plaintext);

        using var bounded = new Passphrase("pw") { MaxWorkFactor = 11 };
        var ex = Assert.Throws<AgeFormatException>(() => new Identities(bounded).Decrypt(file));
        Assert.Contains("work factor 12 exceeds maximum 11", ex.Message, StringComparison.Ordinal);

        using var enough = new Passphrase("pw") { MaxWorkFactor = 12 };
        Assert.Equal(Plaintext, new Identities(enough).Decrypt(file));
    }

    [Fact]
    public void TheMaximum_DefaultsToGoAges()
    {
        using var passphrase = new Passphrase("pw");

        Assert.Equal(22, passphrase.MaxWorkFactor);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    public void AMaximumOutOfRange_IsRefused(int maximum)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Passphrase("pw") { MaxWorkFactor = maximum });
    }

    [Fact]
    public void ADisposedPassphrase_IsUsedNoMore()
    {
        var passphrase = new Passphrase("pw", 10);
        var file = new Recipients(passphrase).Encrypt(Plaintext);
        var stanza = AgeHeader.Read(new MemoryStream(file)).Stanzas[0];

        passphrase.Dispose();
        passphrase.Dispose();

        Assert.Throws<ObjectDisposedException>(() => passphrase.Wrap(new byte[16]));
        Assert.Throws<ObjectDisposedException>(() => passphrase.TryUnwrap(stanza, new byte[16]));
    }

    // A stanza of another type is not the passphrase's, disposed or not.
    [Fact]
    public void AStanzaOfAnotherType_IsNotMatched_EvenWhenDisposed()
    {
        var passphrase = new Passphrase("pw");
        passphrase.Dispose();

        Assert.False(passphrase.TryUnwrap(new Stanza("X25519", ["arg"], new byte[32]), new byte[16]));
    }

    // The work factor is decimal digits with no leading zero, as the spec's ABNF has it.
    [Theory]
    [InlineData("1a")]
    [InlineData("01")]
    [InlineData("x")]
    [InlineData("1-")]
    public void AMalformedWorkFactor_IsAHeaderError(string workFactor)
    {
        using var passphrase = new Passphrase("pw");
        var stanza = new Stanza("scrypt", ["AAAAAAAAAAAAAAAAAAAAAA", workFactor], new byte[32]);

        var ex = Assert.Throws<AgeFormatException>(() => passphrase.TryUnwrap(stanza, new byte[16]));
        Assert.Contains("invalid scrypt work factor", ex.Message, StringComparison.Ordinal);
    }

    // As in go-age, a passphrase is tried before identities that might ask the user for
    // something, so one that would prompt is not asked when the passphrase opens the file.
    [Fact]
    public void APassphrase_IsTriedBeforeAnIdentityThatMightPrompt()
    {
        using var passphrase = new Passphrase("pw", 10);
        var file = new Recipients(passphrase).Encrypt(Plaintext);
        var prompting = new PromptingIdentity();

        Assert.Equal(Plaintext, new Identities(prompting, passphrase).Decrypt(file));
        Assert.Equal(0, prompting.Asked);
    }

    [Fact]
    public void AWrongPassphrase_DoesNotMatch()
    {
        using var right = new Passphrase("right", 10);
        using var wrong = new Passphrase("wrong");
        var stanza = AgeHeader.Read(new MemoryStream(new Recipients(right).Encrypt(Plaintext))).Stanzas[0];

        Assert.False(wrong.TryUnwrap(stanza, new byte[16]));
    }

    private sealed class PromptingIdentity : IIdentity
    {
        public int Asked { get; private set; }

        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
        {
            Asked++;
            return false;
        }
    }
}
