using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// When nothing opens a file, the exception says what the file holds and why each identity, in
/// the order tried, did not open it, without holding the identities or anything secret.
/// </summary>
public class NoIdentityMatchTests
{
    private static readonly byte[] Plaintext = "addressed elsewhere"u8.ToArray();

    [Fact]
    public void ItNamesTheStanzaTypes_AndWhyEachIdentityDidNotMatch()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        using var carol = MlKem768X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var custom = new CustomIdentity();

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(custom, bob, carol).Decrypt(file));

        Assert.Equal(["X25519"], ex.StanzaTypes);
        Assert.Collection(ex.Mismatches,
            m =>
            {
                Assert.StartsWith("X25519Identity (age1", m.Description);
                Assert.Equal(IdentityMismatchReason.NoStanzaForIt, m.Reason);
                Assert.Equal("X25519", m.StanzaType);
            },
            m =>
            {
                Assert.StartsWith("MlKem768X25519Identity (age1pq1", m.Description);
                Assert.Equal(IdentityMismatchReason.NoStanzaOfItsType, m.Reason);
                Assert.Equal("mlkem768x25519", m.StanzaType);
            },
            m =>
            {
                Assert.Equal(nameof(CustomIdentity), m.Description);
                Assert.Equal(IdentityMismatchReason.DidNotMatch, m.Reason);
                Assert.Null(m.StanzaType);
            });

        Assert.Equal(
            $"no identity matched any recipient stanza; the file has X25519; {ex.Mismatches[0].Description}: the file's X25519 stanzas are not for it; "
            + $"{ex.Mismatches[1].Description}: the file has no mlkem768x25519 stanza; CustomIdentity: it opened none of the stanzas",
            ex.Message);
    }

    // As go-age reports them: one entry per stanza, in order, duplicates kept.
    [Fact]
    public void EveryStanza_IsListed()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        using var stranger = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient, bob.Recipient).Encrypt(Plaintext);

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(stranger).Decrypt(file));

        Assert.Equal(["X25519", "X25519"], ex.StanzaTypes);
        Assert.Contains("the file has X25519;", ex.Message);
    }

    [Fact]
    public void APassphrase_SaysTheScryptStanzaIsNotForIt()
    {
        using var right = new Passphrase("right", 10);
        using var wrong = new Passphrase("wrong");
        var file = new Recipients(right).Encrypt(Plaintext);

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(wrong).Decrypt(file));

        var mismatch = Assert.Single(ex.Mismatches);
        Assert.Equal(nameof(Passphrase), mismatch.Description);
        Assert.Equal(IdentityMismatchReason.NoStanzaForIt, mismatch.Reason);
        Assert.Equal("scrypt", mismatch.StanzaType);
    }

    [Fact]
    public void SshIdentities_SayTheirType()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var ed25519 = SshIdentity.Parse(SshKeys.Ed25519Pem());

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(ed25519).Decrypt(file));

        var mismatch = Assert.Single(ex.Mismatches);
        Assert.StartsWith("SshEd25519Identity (ssh-ed25519 AAAA…", mismatch.Description);
        Assert.EndsWith(SshIdentityTail(ed25519) + ")", mismatch.Description);
        Assert.Equal("ssh-ed25519", mismatch.StanzaType);
        Assert.Equal(IdentityMismatchReason.NoStanzaOfItsType, mismatch.Reason);
    }

    [Fact]
    public void RsaAndProtectedSshIdentities_SayTheirType()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var rsa = SshIdentity.Parse(SshKeys.RsaPem());
        var protectedEd25519 = SshIdentity.Parse(Fixture("ed25519_aes256ctr"), () => "pw");
        var protectedRsa = SshIdentity.Parse(Fixture("rsa_aes256ctr"), () => "pw");

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(rsa, protectedEd25519, protectedRsa).Decrypt(file));

        Assert.Equal(["ssh-rsa", "ssh-ed25519", "ssh-rsa"], ex.Mismatches.Select(m => m.StanzaType));
        Assert.All(ex.Mismatches, m => Assert.Equal(IdentityMismatchReason.NoStanzaOfItsType, m.Reason));
        Assert.StartsWith("EncryptedSshIdentity (ssh-ed25519 ", ex.Mismatches[1].Description);
    }

    // A short recipient is shown whole; one with no text not at all.
    [Theory]
    [InlineData("short", "Named (short)")]
    [InlineData("", "Named")]
    [InlineData(null, "Named")]
    public void ARecipientsText_IsShownOnlyWhereThereIsSome(string? text, string expected)
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(new Named(text)).Decrypt(file));

        Assert.Equal(expected, Assert.Single(ex.Mismatches).Description);
    }

    // The last 8 characters of the key's authorized_keys line: what tells two Ed25519 keys apart.
    private static string SshIdentityTail(IIdentity identity) =>
        ((IIdentityWithRecipient)identity).Recipient.ToString()![^8..];

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private sealed class Named(string? text) : IIdentityWithRecipient
    {
        public IRecipient Recipient { get; } = new TextRecipient(text);

        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => false;
    }

    private sealed class TextRecipient(string? text) : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => throw new NotSupportedException();

        public override string? ToString() => text;
    }

    // The description is the type and a public recipient's start: never ToString, which a
    // custom identity might have print its secret.
    [Fact]
    public void NothingSecret_IsInTheMessage()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var leaky = new LeakyIdentity();

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(bob, leaky).Decrypt(file));

        Assert.DoesNotContain("AGE-SECRET-KEY", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(LeakyIdentity.Secret, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(bob.ToSecretString(), ex.Message, StringComparison.Ordinal);
    }

    // A recipient that cannot be had still leaves the type to name the identity by.
    [Fact]
    public void AnIdentityWhoseRecipientThrows_IsNamedByItsType()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        var ex = Assert.Throws<NoIdentityMatchException>(() => new Identities(new ThrowingRecipientIdentity()).Decrypt(file));

        Assert.Equal(nameof(ThrowingRecipientIdentity), Assert.Single(ex.Mismatches).Description);
    }

    // So an SSH recipient can be shown, and listed in a recipients file.
    [Fact]
    public void SshRecipients_PrintAsTheirAuthorizedKeysLine()
    {
        const string ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJQGjgPbMDwrhAEaWNKLdSIHAxiKJDtMCmLj7Zeg844";
        var rsa = ((IIdentityWithRecipient)SshIdentity.Parse(SshKeys.RsaPem())).Recipient.ToString()!;

        Assert.Equal(ed25519, Recipients.ParseOne(ed25519 + " a comment").ToString());
        Assert.StartsWith("ssh-rsa AAAA", rsa);
        Assert.Equal(rsa, Recipients.ParseOne(rsa).ToString());
    }

    [Fact]
    public void ItCanBeThrownByOthers_WithWhatTheyKnow()
    {
        var ex = new NoIdentityMatchException([], []);

        Assert.Equal("no identity matched any recipient stanza; the file has no stanzas", ex.Message);
        Assert.Throws<ArgumentNullException>(() => new NoIdentityMatchException(null!, []));
        Assert.Throws<ArgumentNullException>(() => new NoIdentityMatchException([], null!));
    }

    [Fact]
    public void TheReasons_AreTheSameOnEveryPath()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var with = new Identities(bob);

        var whole = Assert.Throws<NoIdentityMatchException>(() => with.Decrypt(file)).Message;
        var seekable = Assert.Throws<NoIdentityMatchException>(() => with.DecryptReader(new MemoryStream(file))).Message;
        var written = Assert.Throws<NoIdentityMatchException>(() =>
        {
            using var writer = with.DecryptWriter(new MemoryStream());
            writer.Write(file);
        }).Message;

        Assert.Equal(whole, seekable);
        Assert.Equal(whole, written);
    }

    private sealed class CustomIdentity : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => false;
    }

    private sealed class LeakyIdentity : IIdentity
    {
        public const string Secret = "super-secret-material";

        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => false;

        public override string ToString() => Secret;
    }

    private sealed class ThrowingRecipientIdentity : IIdentityWithRecipient
    {
        public IRecipient Recipient => throw new InvalidOperationException("no recipient");

        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => false;
    }
}
