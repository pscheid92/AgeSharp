using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Pins the two identity interface contracts:
///     <see cref="IIdentity" /> extends <see cref="IDisposable" /> with a no-op default, and
///     <see cref="IIdentityWithRecipient" /> exposes the public half without a concrete-type switch.
/// </summary>
public class IdentityInterfaceTests
{
    // --- IIdentity : IDisposable ---

    [Fact]
    public void IIdentity_Extends_IDisposable()
    {
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(IIdentity)));
    }

    [Fact]
    public void DisposeThroughInterface_RunsTheConcreteImplementation()
    {
        // The disposed-guard doubles as the oracle: if the no-op default had shadowed
        // the class implementation, the key would still be readable here.
        IIdentity identity = X25519Identity.Generate();

        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => ((X25519Identity)identity).ToSecretString());
    }

    [Fact]
    public void UsingOverParsedIdentity_DisposesTheConcreteIdentity()
    {
        // The motivating case: Age.ParseIdentity returns IIdentity, so before this
        // contract existed there was no type-level signal to dispose the key material.
        var secret = X25519Identity.Generate().ToSecretString();

        X25519Identity captured;
        using (var parsed = Age.ParseIdentity(secret))
        {
            captured = (X25519Identity)parsed;
        }

        Assert.Throws<ObjectDisposedException>(() => captured.ToSecretString());
    }

    [Fact]
    public void StatelessIdentity_GetsNoOpDispose()
    {
        IIdentity passphrase = new Passphrase("correct-horse-battery-staple");

        passphrase.Dispose();
        passphrase.Dispose();

        // Still usable: the no-op default releases nothing, so behaviour is unchanged.
        Assert.Null(passphrase.Unwrap(new Stanza("X25519", ["arg"], new byte[32])));
    }

    [Fact]
    public void CustomIdentity_NeedNotImplementDispose()
    {
        // Compile-time proof that the default keeps existing implementations valid.
        IIdentity custom = new MinimalIdentity();

        custom.Dispose();

        Assert.Null(custom.Unwrap(new Stanza("X25519", ["arg"], new byte[32])));
    }

    // --- IIdentityWithRecipient ---

    [Theory]
    [MemberData(nameof(IdentitiesWithRecipients))]
    public void BuiltInIdentities_ExposeTheirRecipient(IIdentity identity, string expectedRecipient)
    {
        using (identity)
        {
            var withRecipient = Assert.IsAssignableFrom<IIdentityWithRecipient>(identity);
            Assert.Equal(expectedRecipient, withRecipient.Recipient.ToString());
        }
    }

    [Fact]
    public void PluginIdentity_DoesNotExposeARecipient()
    {
        // A plugin identity's secret lives behind the plugin binary, so the public half
        // is not derivable — the interface must be opt-in, not universal.
        Assert.False(typeof(IIdentityWithRecipient).IsAssignableFrom(typeof(PluginIdentity)));
    }

    [Fact]
    public void Passphrase_DoesNotExposeARecipient()
    {
        // A passphrase is its own recipient, but exposing it here would let `age -e -i`
        // silently turn a passphrase identity file into a recipient. Kept opt-out.
        Assert.False(typeof(IIdentityWithRecipient).IsAssignableFrom(typeof(Passphrase)));
    }

    [Fact]
    public void Recipient_ThroughInterface_ThrowsAfterDispose()
    {
        var identity = X25519Identity.Generate();
        identity.Dispose();

        var withRecipient = (IIdentityWithRecipient)identity;
        Assert.Throws<ObjectDisposedException>(() => withRecipient.Recipient);
    }

    [Fact]
    public void RecipientThroughInterface_RoundTrips()
    {
        // End-to-end: encrypt to the interface-provided recipient, decrypt with the identity.
        using var identity = X25519Identity.Generate();
        var recipient = ((IIdentityWithRecipient)identity).Recipient;

        var ciphertext = Age.Encrypt("interface round-trip"u8, [recipient]);

        Assert.Equal("interface round-trip"u8.ToArray(), Age.Decrypt(ciphertext, [identity]));
    }

    public static TheoryData<IIdentity, string> IdentitiesWithRecipients()
    {
        var x25519 = X25519Identity.Generate();
        var mlkem = MlKem768X25519Identity.Generate();

        return new TheoryData<IIdentity, string>
        {
            { x25519, x25519.Recipient.ToString() },
            { mlkem, mlkem.Recipient.ToString() }
        };
    }

    private sealed class MinimalIdentity : IIdentity
    {
        public byte[]? Unwrap(Stanza stanza)
        {
            return null;
        }
    }
}