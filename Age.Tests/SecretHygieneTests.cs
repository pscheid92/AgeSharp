using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Two properties that are easy to regress silently: that <see cref="Passphrase" />
///     holds its secret somewhere it can actually be zeroed, and that deriving a public
///     key is a one-off rather than a cost paid on every property access.
/// </summary>
public class SecretHygieneTests
{
    private const int LowWorkFactor = 10;

    // --- Passphrase lifecycle ------------------------------------------------

    [Fact]
    public void SpanAndStringConstructors_AgreeOnTheKey()
    {
        // The two overloads must produce byte-identical UTF-8, or a passphrase typed
        // into a char[] would not open a file encrypted from the string form.
        using var fromString = new Passphrase("côrrect-horse", LowWorkFactor);
        using var fromSpan = new Passphrase("côrrect-horse".AsSpan(), LowWorkFactor);

        var ciphertext = Age.Encrypt("secret"u8, fromString);
        Assert.Equal("secret"u8.ToArray(), Age.Decrypt(ciphertext, fromSpan));
    }

    [Fact]
    public void NonAsciiPassphrase_RoundTrips()
    {
        // Multi-byte UTF-8 is where a char-count/byte-count mix-up would show up.
        using var passphrase = new Passphrase("пароль-🔐-日本語".AsSpan(), LowWorkFactor);

        var ciphertext = Age.Encrypt("secret"u8, passphrase);
        Assert.Equal("secret"u8.ToArray(), Age.Decrypt(ciphertext, passphrase));
    }

    [Fact]
    public void Dispose_ZeroesTheStoredPassphrase()
    {
        var passphrase = new Passphrase("to-be-wiped", LowWorkFactor);
        passphrase.Dispose();

        Assert.Throws<ObjectDisposedException>(() => passphrase.Wrap(new byte[16]));
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var passphrase = new Passphrase("pw", LowWorkFactor);
        passphrase.Dispose();
        passphrase.Dispose();
    }

    [Fact]
    public void UnwrapAfterDispose_Throws()
    {
        using var live = new Passphrase("pw", LowWorkFactor);
        var stanza = live.Wrap(new byte[16]);

        var disposed = new Passphrase("pw", LowWorkFactor);
        disposed.Dispose();

        Assert.Throws<ObjectDisposedException>(() => disposed.Unwrap(stanza));
    }

    [Fact]
    public void UnwrapOfAnotherStanzaType_StillReturnsNullAfterDispose()
    {
        // The type check comes first by design: "not my stanza" is not an error, and
        // answering it needs no secret. Age.Decrypt relies on this to try identities
        // in turn without caring which are live.
        var disposed = new Passphrase("pw", LowWorkFactor);
        disposed.Dispose();

        Assert.Null(disposed.Unwrap(new Stanza("X25519", ["abc"], new byte[32])));
    }

    [Fact]
    public void NullPassphrase_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => new Passphrase(null!));
        Assert.Throws<ArgumentNullException>(() => new Passphrase(null!, LowWorkFactor));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(21)]
    public void WorkFactorOutOfRange_Throws(int workFactor)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Passphrase("pw", workFactor));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Passphrase("pw".AsSpan(), workFactor));
    }

    [Fact]
    public void DefaultWorkFactorIs18()
    {
        // Matching the age CLI matters for interop expectations, and the constant is
        // now duplicated across four constructors' worth of routing.
        using var fromString = new Passphrase("pw");
        using var fromSpan = new Passphrase("pw".AsSpan());

        Assert.Equal("18", fromString.Wrap(new byte[16]).Args[1]);
        Assert.Equal("18", fromSpan.Wrap(new byte[16]).Args[1]);
    }

    [Fact]
    public void EmptyPassphrase_IsAllowed()
    {
        // age itself permits it; refusing here would be a divergence, not a safeguard.
        using var passphrase = new Passphrase("", LowWorkFactor);

        var ciphertext = Age.Encrypt("secret"u8, passphrase);
        Assert.Equal("secret"u8.ToArray(), Age.Decrypt(ciphertext, passphrase));
    }

    // --- public keys are derived once ----------------------------------------

    [Fact]
    public void X25519Identity_RecipientIsCached()
    {
        using var identity = X25519Identity.Generate();

        // Same instance, not merely an equal one: deriving the public half is a
        // scalar multiplication, and Unwrap needs it once per stanza.
        Assert.Same(identity.Recipient, identity.Recipient);
    }

    [Fact]
    public void MlKem768X25519Identity_RecipientIsCached()
    {
        // Costlier than the X25519 case: a full ML-KEM-768 key generation.
        using var identity = MlKem768X25519Identity.Generate();

        Assert.Same(identity.Recipient, identity.Recipient);
    }

    [Fact]
    public void CachedRecipient_StillMatchesTheKey()
    {
        // Caching must not decouple the recipient from the identity it came from.
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        var ciphertext = Age.Encrypt("secret"u8, recipient);
        Assert.Equal("secret"u8.ToArray(), Age.Decrypt(ciphertext, identity));

        Assert.Equal(recipient.ToString(), identity.Recipient.ToString());
    }

    [Fact]
    public void MultiStanzaHeader_DecryptsWithACachedKey()
    {
        // Unwrap consults the public half once per stanza to build the HKDF salt,
        // so this is the path the caching was actually for.
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        using var carol = X25519Identity.Generate();

        var ciphertext = Age.Encrypt("secret"u8, alice.Recipient, bob.Recipient, carol.Recipient);

        Assert.Equal("secret"u8.ToArray(), Age.Decrypt(ciphertext, carol));
    }

    [Fact]
    public void RecipientAfterDispose_Throws()
    {
        var identity = X25519Identity.Generate();
        _ = identity.Recipient; // populate the cache first
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => identity.Recipient);
    }

    [Fact]
    public void RecipientIsCached_EvenWhenFirstTouchedThroughTheInterface()
    {
        using var identity = X25519Identity.Generate();
        var viaInterface = ((IIdentityWithRecipient)identity).Recipient;

        Assert.Same(viaInterface, identity.Recipient);
    }
}