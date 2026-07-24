using Age.Format;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The label-set contract on encryption: all recipients must carry the same
/// label set, compared order-insensitively with set semantics.
/// </summary>
public class LabelsTests
{
    private sealed class StubRecipient(params string[] labels) : IRecipient
    {
        public IReadOnlyCollection<string> Labels => labels;

        public Stanza Wrap(ReadOnlySpan<byte> fileKey) =>
            new("test", ["arg"], new byte[32]);
    }

    private static void Encrypt(params IRecipient[] recipients)
    {
        using var input = new MemoryStream("hello"u8.ToArray());
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, recipients);
    }

    private static void AssertRejected(params IRecipient[] recipients)
    {
        var ex = Assert.Throws<AgeException>(() => Encrypt(recipients));
        Assert.Contains("security labels", ex.Message);
    }

    [Fact]
    public void EqualSets_SameOrder_Allowed() =>
        Encrypt(new StubRecipient("a", "b"), new StubRecipient("a", "b"));

    [Fact]
    public void EqualSets_DifferentOrder_Allowed() =>
        Encrypt(new StubRecipient("a", "b"), new StubRecipient("b", "a"));

    [Fact]
    public void Duplicates_CollapseToSet() =>
        Encrypt(new StubRecipient("a", "a"), new StubRecipient("a"));

    [Fact]
    public void Subset_Rejected() =>
        AssertRejected(new StubRecipient("a"), new StubRecipient("a", "b"));

    [Fact]
    public void Superset_Rejected() =>
        AssertRejected(new StubRecipient("a", "b"), new StubRecipient("a"));

    [Fact]
    public void Disjoint_Rejected() =>
        AssertRejected(new StubRecipient("a"), new StubRecipient("b"));

    [Fact]
    public void EmptyVsNonEmpty_Rejected() =>
        AssertRejected(new StubRecipient(), new StubRecipient("a"));

    [Fact]
    public void SingleRecipient_AnyLabels_Allowed() =>
        Encrypt(new StubRecipient("anything", "goes", "alone"));

    [Fact]
    public void TwoPqRecipients_Allowed()
    {
        // Real recipients with matching non-empty label sets round-trip
        using var a = MlKem768X25519Identity.Generate();
        using var b = MlKem768X25519Identity.Generate();

        using var input = new MemoryStream("hello"u8.ToArray());
        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(input, encrypted, a.Recipient, b.Recipient);

        encrypted.Position = 0;
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(encrypted, output, b);
        Assert.Equal("hello"u8.ToArray(), output.ToArray());
    }

    [Fact]
    public void PqMixedWithClassical_Rejected()
    {
        using var pq = MlKem768X25519Identity.Generate();
        using var classical = X25519Identity.Generate();
        AssertRejected(pq.Recipient, classical.Recipient);
    }
}
