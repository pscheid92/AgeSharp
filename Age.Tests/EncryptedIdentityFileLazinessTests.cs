using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A passphrase-protected identity file is an identity that asks for its passphrase only when a
/// file is tried against it, and then once, clearing what it was given.
/// </summary>
public class EncryptedIdentityFileLazinessTests
{
    private static readonly byte[] Plaintext = "for the key in the file"u8.ToArray();

    [Fact]
    public void ItOpensFilesForTheKeysItHolds()
    {
        using var key = X25519Identity.Generate();
        var asked = 0;
        using var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => { asked++; return "pw".ToCharArray(); });

        Assert.Equal(0, asked);

        var file = new Recipients(key.Recipient).Encrypt(Plaintext);
        Assert.Equal(Plaintext, new Identities(identityFile).Decrypt(file));
        Assert.Equal(Plaintext, new Identities(identityFile).Decrypt(file));
        Assert.Equal(1, asked);
    }

    // AgeSharp's own identities are tried first, so a file one of them opens never asks.
    [Fact]
    public void ItIsNotAsked_WhenAnotherIdentityOpensTheFile()
    {
        using var key = X25519Identity.Generate();
        using var other = X25519Identity.Generate();
        var asked = 0;
        using var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => { asked++; return "pw".ToCharArray(); });

        var file = new Recipients(other.Recipient).Encrypt(Plaintext);

        Assert.Equal(Plaintext, new Identities(identityFile, other).Decrypt(file));
        Assert.Equal(0, asked);
    }

    [Fact]
    public void ThePassphraseCharacters_AreClearedOnceUsed()
    {
        using var key = X25519Identity.Generate();
        var given = "pw".ToCharArray();
        using var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => given);

        Assert.Single(identityFile.Recipients);
        Assert.All(given, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void AWrongPassphrase_IsSaid_AndAskedAgainNextTime()
    {
        using var key = X25519Identity.Generate();
        var answers = new Queue<string>(["wrong", "pw"]);
        using var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => answers.Dequeue().ToCharArray());
        var file = new Recipients(key.Recipient).Encrypt(Plaintext);

        var ex = Assert.Throws<AgeException>(() => new Identities(identityFile).Decrypt(file));
        Assert.Contains("passphrase is wrong", ex.Message, StringComparison.Ordinal);
        Assert.IsType<NoIdentityMatchException>(ex.InnerException);

        Assert.Equal(Plaintext, new Identities(identityFile).Decrypt(file));
    }

    [Fact]
    public void AFileNotEncryptedToAPassphrase_IsSaid()
    {
        using var key = X25519Identity.Generate();
        var notPassphraseProtected = new Recipients(key.Recipient).Encrypt(Encoding.UTF8.GetBytes(key.ToSecretString()));
        using var identityFile = new EncryptedIdentityFile(notPassphraseProtected, () => "pw".ToCharArray());

        Assert.Throws<AgeException>(() => identityFile.Recipients);
    }

    [Fact]
    public void ACallbackReturningNull_IsAnError()
    {
        using var key = X25519Identity.Generate();
        using var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => null!);

        Assert.Throws<InvalidOperationException>(() => identityFile.Recipients);
    }

    [Fact]
    public void ANullCallback_IsRefused()
    {
        Assert.Throws<ArgumentNullException>(() => new EncryptedIdentityFile([], null!));
    }

    // The file is copied: changing the caller's array afterwards changes nothing.
    [Fact]
    public void TheContents_AreCopied()
    {
        using var key = X25519Identity.Generate();
        var contents = Protect(key.ToSecretString());
        using var identityFile = new EncryptedIdentityFile(contents, () => "pw".ToCharArray());
        Array.Clear(contents);

        Assert.Equal(key.Recipient.ToString(), Assert.Single(identityFile.Recipients).ToString());
    }

    [Fact]
    public void ItCanHoldIdentitiesWithoutARecipient()
    {
        using var key = X25519Identity.Generate();
        var plugin = AgeSharp.Crypto.Bech32.Encode("age-plugin-example-", [1, 2, 3]).ToUpperInvariant();
        using var identityFile = new EncryptedIdentityFile(Protect($"{key.ToSecretString()}\n{plugin}\n"), () => "pw".ToCharArray());

        Assert.Equal(key.Recipient.ToString(), Assert.Single(identityFile.Recipients).ToString());
    }

    [Fact]
    public void Disposing_ClearsTheIdentitiesItDecrypted_AndEndsIt()
    {
        using var key = X25519Identity.Generate();
        var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => "pw".ToCharArray());
        var file = new Recipients(key.Recipient).Encrypt(Plaintext);
        var stanza = AgeHeader.Read(new MemoryStream(file)).Stanzas[0];
        Assert.True(identityFile.TryUnwrap(stanza, new byte[16]));

        // The decrypted identities never leave the file, so only reflection can show that
        // disposing it clears their keys. A renamed field fails here, loudly.
        var decrypted = (Identities)typeof(EncryptedIdentityFile)
            .GetField("_identities", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(identityFile)!;
        var inner = (X25519Identity)decrypted[0];

        identityFile.Dispose();
        identityFile.Dispose();

        Assert.Throws<ObjectDisposedException>(() => inner.ToSecretString());
        Assert.Throws<ObjectDisposedException>(() => identityFile.TryUnwrap(stanza, new byte[16]));
        Assert.Throws<ObjectDisposedException>(() => identityFile.Recipients);
    }

    [Fact]
    public void DisposingBeforeUse_AsksForNothing()
    {
        var asked = false;
        var identityFile = new EncryptedIdentityFile([], () => { asked = true; return [] ; });

        identityFile.Dispose();

        Assert.False(asked);
    }

    [Fact]
    public void AStanzaForNoKeyInTheFile_IsNotMatched()
    {
        using var key = X25519Identity.Generate();
        using var other = X25519Identity.Generate();
        using var identityFile = new EncryptedIdentityFile(Protect(key.ToSecretString()), () => "pw".ToCharArray());
        var stanza = AgeHeader.Read(new MemoryStream(new Recipients(other.Recipient).Encrypt(Plaintext))).Stanzas[0];

        Assert.False(identityFile.TryUnwrap(stanza, new byte[16]));
    }

    // What age -p writes.
    private static byte[] Protect(string identityFileText)
    {
        using var passphrase = new Passphrase("pw", 10);
        return new Recipients(passphrase).Encrypt(Encoding.UTF8.GetBytes(identityFileText), new AgeEncryptOptions { Armor = true });
    }
}
