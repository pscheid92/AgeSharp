using System.Security.Cryptography;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Pins the disposal contract for the identity types that derive their public
///     half from zeroizable secret material: once disposed, every member that would
///     read that material throws <see cref="ObjectDisposedException" /> rather than
///     silently returning a value derived from the zeroed buffer.
///     <para>
///         Before this contract existed, <c>ToSecretString()</c> on a disposed identity
///         returned a well-formed bech32 string — correct HRP, valid checksum — encoding
///         the all-zero key. Writing that to an identity file produced a key file anyone
///         could derive, with no error anywhere.
///     </para>
///     <para>
///         The SSH identity types keep their public halves outside the zeroized buffer,
///         so their disposal facts live with their key generators in
///         <c>SshTests.cs</c> (<c>SshEd25519RecipientIdentityTests</c> /
///         <c>SshRsaRecipientIdentityTests</c>).
///     </para>
/// </summary>
public class IdentityLifecycleTests
{
    // --- the regression: a disposed identity must not hand back an all-zero key ---

    [Fact]
    public void X25519_ToSecretString_AfterDispose_Throws_RatherThanReturningZeroKey()
    {
        var identity = X25519Identity.Generate();

        // Read once while live so the test fails loudly if the guard is ever applied
        // so broadly that the member stops working before disposal.
        Assert.StartsWith("AGE-SECRET-KEY-1", identity.ToSecretString(), StringComparison.Ordinal);

        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.ToSecretString());
    }

    [Fact]
    public void MlKem_ToSecretString_AfterDispose_Throws_RatherThanReturningZeroSeed()
    {
        var identity = MlKem768X25519Identity.Generate();

        Assert.StartsWith("AGE-SECRET-KEY-PQ-1", identity.ToSecretString(), StringComparison.Ordinal);

        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.ToSecretString());
    }

    // --- Recipient derives from the secret, so it must be guarded too ---

    [Fact]
    public void X25519_Recipient_AfterDispose_Throws()
    {
        var identity = X25519Identity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.Recipient);
    }

    [Fact]
    public void MlKem_Recipient_AfterDispose_Throws()
    {
        var identity = MlKem768X25519Identity.Generate();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.Recipient);
    }

    [Fact]
    public void X25519_Unwrap_AfterDispose_Throws()
    {
        var identity = X25519Identity.Generate();
        var stanza = identity.Recipient.Wrap(FileKey())[0];
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.TryUnwrap(stanza, new byte[Age.FileKeySize]));
    }

    [Fact]
    public void MlKem_Unwrap_AfterDispose_Throws()
    {
        var identity = MlKem768X25519Identity.Generate();
        var stanza = identity.Recipient.Wrap(FileKey())[0];
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.TryUnwrap(stanza, new byte[Age.FileKeySize]));
    }

    // --- ToString is the deliberate exception: diagnostics must never fail ---

    [Fact]
    public void X25519_ToString_AfterDispose_ReturnsMarker_AndDoesNotThrow()
    {
        var identity = X25519Identity.Generate();
        identity.Dispose();

        var text = identity.ToString();

        Assert.Equal("X25519Identity(disposed)", text);
        Assert.DoesNotContain("AGE-SECRET-KEY", text, StringComparison.Ordinal);
        Assert.DoesNotContain("age1", text, StringComparison.Ordinal);
    }

    [Fact]
    public void MlKem_ToString_AfterDispose_ReturnsMarker_AndDoesNotThrow()
    {
        var identity = MlKem768X25519Identity.Generate();
        identity.Dispose();

        var text = identity.ToString();

        Assert.Equal("MlKem768X25519Identity(disposed)", text);
        Assert.DoesNotContain("AGE-SECRET-KEY", text, StringComparison.Ordinal);
        Assert.DoesNotContain("age1", text, StringComparison.Ordinal);
    }

    // --- a recipient taken before disposal keeps working: it owns its own copy ---

    [Fact]
    public void X25519_RecipientTakenBeforeDispose_StaysValid()
    {
        var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;
        var expected = recipient.ToString();

        identity.Dispose();

        Assert.Equal(expected, recipient.ToString());
        Assert.NotNull(recipient.Wrap(FileKey())[0]);
    }

    [Fact]
    public void MlKem_RecipientTakenBeforeDispose_StaysValid()
    {
        var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;
        var expected = recipient.ToString();

        identity.Dispose();

        Assert.Equal(expected, recipient.ToString());
        Assert.NotNull(recipient.Wrap(FileKey())[0]);
    }

    // --- disposal stays idempotent ---

    [Fact]
    public void X25519_DoubleDispose_DoesNotThrow()
    {
        var identity = X25519Identity.Generate();

        identity.Dispose();
        identity.Dispose();
    }

    [Fact]
    public void MlKem_DoubleDispose_DoesNotThrow()
    {
        var identity = MlKem768X25519Identity.Generate();

        identity.Dispose();
        identity.Dispose();
    }

    private static byte[] FileKey()
    {
        var key = new byte[16];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}