using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Regression tests for S5: a disposed identity must not keep deriving public
/// material. Before the fix, <c>Recipient</c> and <c>ToSecretString</c> operated
/// on the zeroed key and silently returned the all-zero-seed keypair — a
/// well-formed, world-derivable recipient — while <c>Unwrap</c> on the same
/// instance correctly threw.
/// </summary>
public class IdentityDisposalTests
{
    // The recipient/secret every disposed identity collapsed to before the fix.
    private const string AllZeroX25519Recipient =
        "age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p";

    [Fact]
    public void X25519Identity_Recipient_AfterDispose_Throws()
    {
        var identity = X25519Identity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.Recipient);
    }

    [Fact]
    public void X25519Identity_ToSecretString_AfterDispose_Throws()
    {
        var identity = X25519Identity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.ToSecretString());
    }

    [Fact]
    public void X25519Identity_ToString_AfterDispose_IsRedacted_AndDoesNotThrow()
    {
        var identity = X25519Identity.Generate();
        identity.Dispose();

        var text = identity.ToString();

        Assert.Equal("X25519Identity(disposed)", text);
        Assert.DoesNotContain(AllZeroX25519Recipient, text, StringComparison.Ordinal);
    }

    [Fact]
    public void X25519Identity_TwoDisposedIdentities_DoNotCollapseToOneKeypair()
    {
        var a = X25519Identity.Generate();
        var b = X25519Identity.Generate();
        a.Dispose();
        b.Dispose();

        // Before the fix both returned the same all-zero-seed recipient.
        Assert.Throws<ObjectDisposedException>(() => a.Recipient);
        Assert.Throws<ObjectDisposedException>(() => b.Recipient);
    }

    [Fact]
    public void MlKemIdentity_Recipient_AfterDispose_Throws()
    {
        var identity = MlKem768X25519Identity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.Recipient);
    }

    [Fact]
    public void MlKemIdentity_ToSecretString_AfterDispose_Throws()
    {
        var identity = MlKem768X25519Identity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.ToSecretString());
    }

    [Fact]
    public void MlKemIdentity_ToString_AfterDispose_IsRedacted_AndDoesNotThrow()
    {
        var identity = MlKem768X25519Identity.Generate();
        identity.Dispose();

        Assert.Equal("MlKem768X25519Identity(disposed)", identity.ToString());
    }

    [Fact]
    public void LiveIdentities_StillExposeRecipientAndSecret()
    {
        // Guard against over-eager guarding: the undisposed path is unchanged.
        using var x = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();

        Assert.StartsWith("age1", x.Recipient.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("AGE-SECRET-KEY-1", x.ToSecretString(), StringComparison.Ordinal);
        Assert.StartsWith("X25519Identity(age1", x.ToString(), StringComparison.Ordinal);

        Assert.StartsWith("age1pq1", pq.Recipient.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("AGE-SECRET-KEY-PQ-1", pq.ToSecretString(), StringComparison.Ordinal);
        Assert.StartsWith("MlKem768X25519Identity(age1pq1", pq.ToString(), StringComparison.Ordinal);
    }
}
