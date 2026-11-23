using System.Text;
using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Inputs on which AgeSharp once decided differently from go-age v1.3.2, now decided as go-age
/// does: a file that one opens, the other opens; a malformed one, both refuse.
/// </summary>
public class GoAgeAlignmentTests
{
    // --- ssh-ed25519 ------------------------------------------------------------------------

    // go-age checks the ephemeral share before it compares the tag (agessh.go, unwrap), so a
    // malformed stanza is malformed whichever key it names.
    [Theory]
    [InlineData("not-base64!")]
    [InlineData("AAAA")]
    public void AMalformedShare_IsMalformed_EvenForAnotherKey(string share)
    {
        using var identity = SshIdentity.Parse(SshKeys.Ed25519Pem());
        var stanza = new Stanza("ssh-ed25519", ["AAAAAA", share], new byte[32]);

        Assert.Throws<AgeFormatException>(() => identity.TryUnwrap(stanza, new byte[FileKey.Size]));
    }

    // go-age does not check the body's length: one that is not a wrapped file key fails to
    // decrypt, which is "not for this identity".
    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public void ABodyOfTheWrongLength_IsNotAMatch(int length)
    {
        using var identity = (SshEd25519Identity)SshIdentity.Parse(SshKeys.Ed25519Pem());
        var stanza = Assert.Single(identity.Recipient.Wrap(new byte[FileKey.Size]));
        var cut = new Stanza(stanza.Type, [.. stanza.Args], stanza.Body.ToArray().AsSpan(0, Math.Min(length, 32)).ToArray().Concat(new byte[Math.Max(0, length - 32)]).ToArray());

        Assert.False(identity.TryUnwrap(cut, new byte[FileKey.Size]));
    }

    // So a file whose first stanza is such a body still opens with the stanza after it.
    [Fact]
    public void AFileWithAShortBodyBeforeTheRealStanza_Opens()
    {
        using var identity = (SshEd25519Identity)SshIdentity.Parse(SshKeys.Ed25519Pem());
        var stanza = Assert.Single(identity.Recipient.Wrap(new byte[FileKey.Size]));
        var cut = new Stanza(stanza.Type, [.. stanza.Args], stanza.Body.ToArray()[..31]);

        Assert.False(identity.TryUnwrap(cut, new byte[FileKey.Size]));
        Assert.True(((IIdentity)identity).TryUnwrap(new[] { cut, stanza }, new byte[FileKey.Size]));
    }

    // --- Armor --------------------------------------------------------------------------------

    // go-age requires the begin line exactly (armor.go: string(line) != Header); whitespace may
    // stand on lines of its own before it, not in front of it.
    [Theory]
    [InlineData("  ")]
    [InlineData("\t")]
    public void AnIndentedBeginLine_IsRefused(string indent)
    {
        using var key = X25519Identity.Generate();
        var armored = Encoding.ASCII.GetString(new Recipients(key.Recipient).Encrypt("hi"u8.ToArray(), new AgeEncryptOptions { Armor = true }));
        var indented = Encoding.ASCII.GetBytes(indent + armored);

        Assert.Throws<AgeFormatException>(() => new Identities(key).Decrypt(indented));
        Assert.Throws<AgeFormatException>(() => Armor.Decode(new MemoryStream(indented), new MemoryStream()));

        using var pushed = new MemoryStream();
        Assert.Throws<AgeFormatException>(() =>
        {
            using var writer = new Identities(key).DecryptWriter(pushed);
            writer.Write(indented);
        });
    }

    // --- Bech32 -------------------------------------------------------------------------------

    // go-age folds ASCII letters only (internal/bech32): Unicode case folding turns U+212A KELVIN
    // SIGN into k, which made "AGE-SECRET-KEY-1…" read as a valid key here.
    [Fact]
    public void AKeyWithANonAsciiLetter_IsRefused()
    {
        using var key = X25519Identity.Generate();
        var kelvin = key.ToSecretString().Replace("KEY", "KEY");

        Assert.Throws<FormatException>(() => X25519Identity.Parse(kelvin));
        Assert.Throws<FormatException>(() => Identities.Parse(kelvin));
        Assert.Throws<FormatException>(() => Bech32.Decode("age1Kqqqqqqqq"));
    }
}
