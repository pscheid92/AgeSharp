using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The two extension points, as a custom recipient or identity sees them: a recipient wraps a
/// file key into one or more stanzas, with the security labels that wrapping carries; an identity
/// writes a file key into a buffer the caller owns. Each test uses only these contracts and the
/// encrypt and decrypt entry points.
/// </summary>
public class RecipientIdentityContractTests
{
    private const int FileKeySize = 16;
    private static readonly byte[] Plaintext = "wrapped by a custom recipient"u8.ToArray();

    // --- Recipients ---------------------------------------------------------------------------

    // A recipient may stand for several keys: every stanza it produces lands in the header, and
    // each one opens the file.
    [Fact]
    public void ARecipientsStanzas_AllLandInTheHeader()
    {
        using var first = X25519Identity.Generate();
        using var second = X25519Identity.Generate();
        var group = new GroupRecipient(first.Recipient, second.Recipient);

        var ciphertext = Encrypt(group);

        Assert.Equal(2, AgeHeader.Parse(new MemoryStream(ciphertext)).RecipientCount);
        Assert.Equal(Plaintext, Decrypt(ciphertext, first));
        Assert.Equal(Plaintext, Decrypt(ciphertext, second));
    }

    // A header without this recipient's stanza would encrypt the file to nobody it named.
    [Fact]
    public void ARecipientThatProducesNoStanzas_IsRefused()
    {
        var ex = Assert.Throws<AgeException>(() => Encrypt(new GroupRecipient()));

        Assert.Contains("no stanzas", ex.Message);
    }

    // Null is the same mistake as an empty list: a custom Wrap returning null, or a
    // LabelledStanzas left at its default.
    [Fact]
    public void ARecipientThatProducesNull_IsRefused()
    {
        Assert.Contains("no stanzas", Assert.Throws<AgeException>(() => Encrypt(new NullRecipient())).Message);
        Assert.Contains("no stanzas", Assert.Throws<AgeException>(() => Encrypt(new DefaultLabelledRecipient())).Message);
    }

    [Fact]
    public void RecipientsWithTheSameLabels_Mix_InAnyOrder()
    {
        using var identity = X25519Identity.Generate();
        var a = new LabelledRecipient(identity.Recipient, "postquantum", "hardware");
        var b = new LabelledRecipient(identity.Recipient, "hardware", "postquantum");

        Assert.Equal(Plaintext, Decrypt(Encrypt(a, b), identity));
    }

    // The refusal names both sets, each in a stable order.
    [Fact]
    public void RecipientsWithDifferentLabels_AreNamedInTheRefusal()
    {
        using var identity = X25519Identity.Generate();
        var a = new LabelledRecipient(identity.Recipient, "hardware", "acme");
        var b = new LabelledRecipient(identity.Recipient, "globex");

        var ex = Assert.Throws<AgeException>(() => Encrypt(a, b));

        Assert.Contains("\"acme\", \"hardware\"", ex.Message);
        Assert.Contains("\"globex\"", ex.Message);
    }

    [Theory]
    [InlineData(new[] { "postquantum" }, new[] { "hardware" })]
    [InlineData(new[] { "postquantum" }, new[] { "postquantum", "hardware" })]
    [InlineData(new[] { "postquantum" }, new string[0])]
    [InlineData(new[] { "postquantum" }, new[] { "PostQuantum" })]
    public void RecipientsWithDifferentLabels_AreRefused(string[] labels, string[] others)
    {
        using var identity = X25519Identity.Generate();
        var a = new LabelledRecipient(identity.Recipient, labels);
        var b = new LabelledRecipient(identity.Recipient, others);

        Assert.Throws<AgeException>(() => Encrypt(a, b));
    }

    // A recipient that carries no labels has an empty set, so it cannot join a labelled one —
    // which is what keeps a classical recipient out of a post-quantum file.
    [Fact]
    public void AnUnlabelledRecipient_CannotJoinALabelledOne()
    {
        using var classical = X25519Identity.Generate();
        using var postQuantum = MlKem768X25519Identity.Generate();

        Assert.Throws<AgeException>(() => Encrypt(classical.Recipient, postQuantum.Recipient));
    }

    // --- Identities ---------------------------------------------------------------------------

    [Fact]
    public void AnIdentity_WritesTheFileKeyIntoTheCallersBuffer()
    {
        using var identity = X25519Identity.Generate();
        var fileKey = Enumerable.Range(1, FileKeySize).Select(i => (byte)i).ToArray();
        var stanza = Assert.Single(identity.Recipient.Wrap(fileKey));
        var buffer = new byte[FileKeySize];

        Assert.True(identity.TryUnwrap(stanza, buffer));
        Assert.Equal(fileKey, buffer);
    }

    [Fact]
    public void AnIdentityThatDeclines_LeavesTheBufferAlone()
    {
        using var identity = X25519Identity.Generate();
        using var someoneElse = X25519Identity.Generate();
        var stanza = Assert.Single(someoneElse.Recipient.Wrap(new byte[FileKeySize]));
        var buffer = Enumerable.Repeat((byte)0xAA, FileKeySize).ToArray();

        Assert.False(identity.TryUnwrap(stanza, buffer));
        Assert.All(buffer, b => Assert.Equal(0xAA, b));
    }

    // Most identities implement only the single-stanza TryUnwrap; the list overload's default
    // tries each stanza, so decryption finds the one that is theirs.
    [Fact]
    public void ACustomIdentity_NeedsOnlyTheSingleStanzaTryUnwrap()
    {
        using var inner = X25519Identity.Generate();
        using var someoneElse = X25519Identity.Generate();
        var ciphertext = Encrypt(someoneElse.Recipient, inner.Recipient);

        Assert.Equal(Plaintext, Decrypt(ciphertext, new SingleStanzaIdentity(inner)));
    }

    // Held through the interface, as parsing returns it, an identity can be using-scoped without
    // knowing its type; one that holds nothing secret need not write a Dispose.
    [Fact]
    public void AnIdentity_IsDisposableThroughTheInterface()
    {
        using IIdentity identity = new SingleStanzaIdentity(X25519Identity.Generate());

        Assert.IsAssignableFrom<IDisposable>(identity);
    }

    // AgeSharp's identities that hold their key say so, and their recipient is one they can
    // decrypt for. A plugin identity does not yet: it would need a recipient that speaks
    // recipient-v1 with add-identity (see TODO.md).
    public static TheoryData<string> IdentitiesWithRecipients => new() { "X25519", "ML-KEM-768-X25519", "SSH Ed25519", "SSH RSA", "protected SSH" };

    [Theory]
    [MemberData(nameof(IdentitiesWithRecipients))]
    public void AnIdentityThatKnowsItsRecipient_DecryptsWhatIsEncryptedToIt(string kind)
    {
        using var identity = Assert.IsAssignableFrom<IIdentityWithRecipient>(Identity(kind));

        Assert.Equal(Plaintext, Decrypt(Encrypt(identity.Recipient), identity));
    }

    private static IIdentity Identity(string kind) => kind switch
    {
        "X25519" => X25519Identity.Generate(),
        "ML-KEM-768-X25519" => MlKem768X25519Identity.Generate(),
        "SSH Ed25519" => AgeKeygen.ParseSshIdentity(SshKey("ed25519_plain")),
        "SSH RSA" => AgeKeygen.ParseSshIdentity(SshKey("rsa_plain")),
        "protected SSH" => AgeKeygen.ParseSshIdentity(SshKey("ed25519_aes256gcm"), () => "hunter2"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    // --- Helpers ------------------------------------------------------------------------------

    private sealed class GroupRecipient(params IRecipient[] members) : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
        {
            var stanzas = new List<Stanza>();

            foreach (var member in members)
                stanzas.AddRange(member.Wrap(fileKey));

            return stanzas;
        }
    }

    private sealed class LabelledRecipient(IRecipient inner, params string[] labels) : IRecipientWithLabels
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => inner.Wrap(fileKey);

        public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) => new(inner.Wrap(fileKey), labels);
    }

    private sealed class NullRecipient : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => null!;
    }

    private sealed class DefaultLabelledRecipient : IRecipientWithLabels
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => WrapWithLabels(fileKey).Stanzas;

        public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) => default;
    }

    private sealed class SingleStanzaIdentity(X25519Identity inner) : IIdentity
    {
        public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) => inner.TryUnwrap(stanza, fileKey);
    }

    private static string SshKey(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private static byte[] Encrypt(params IRecipient[] recipients)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(Plaintext), output, recipients);
        return output.ToArray();
    }

    private static byte[] Decrypt(byte[] ciphertext, IIdentity identity)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(new MemoryStream(ciphertext), output, identity);
        return output.ToArray();
    }
}
