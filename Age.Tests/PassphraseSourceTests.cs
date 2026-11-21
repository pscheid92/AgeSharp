using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Every protected key asks for its passphrase the same way: characters, cleared once used, or
/// null to cancel. A source that fails is an <see cref="AgeException"/>; one that cancels by
/// throwing <see cref="OperationCanceledException"/> is let through.
/// </summary>
public class PassphraseSourceTests
{
    private const string SshPassphrase = "hunter2";
    private static readonly byte[] Plaintext = "for a protected key"u8.ToArray();

    public static TheoryData<string> Kinds => ["ssh", "identity file"];

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ThePassphrase_IsClearedOnceUsed(string kind)
    {
        var given = (kind == "ssh" ? SshPassphrase : "pw").ToCharArray();
        var (identity, file) = Protected(kind, () => given);

        using (identity)
            Assert.Equal(Plaintext, new Identities(identity).Decrypt(file));

        Assert.All(given, c => Assert.Equal('\0', c));
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void Null_Cancels(string kind)
    {
        var (identity, file) = Protected(kind, () => null);

        using (identity)
        {
            var ex = Assert.Throws<AgeException>(() => new Identities(identity).Decrypt(file));
            Assert.Contains("no passphrase was given", ex.Message);
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ASourceThatFails_IsAnAgeException(string kind)
    {
        var (identity, file) = Protected(kind, () => throw new IOException("no terminal"));

        using (identity)
        {
            var ex = Assert.Throws<AgeException>(() => new Identities(identity).Decrypt(file));
            Assert.Contains("failed to obtain the passphrase", ex.Message);
            Assert.IsType<IOException>(ex.InnerException);
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ASourceThatCancels_IsLetThrough(string kind)
    {
        var (identity, file) = Protected(kind, () => throw new OperationCanceledException());

        using (identity)
            Assert.Throws<OperationCanceledException>(() => new Identities(identity).Decrypt(file));
    }

    // A protected key of the given kind, and a file encrypted to it.
    private static (IIdentity, byte[]) Protected(string kind, Func<char[]?> passphrase)
    {
        if (kind == "ssh")
        {
            var pem = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", "ed25519_aes256ctr"));
            var identity = SshIdentity.Parse(pem, passphrase);
            var recipient = ((IIdentityWithRecipient)identity).Recipient;
            return (identity, new Recipients(recipient).Encrypt(Plaintext));
        }

        using var key = X25519Identity.Generate();
        using var protecting = new Passphrase("pw", 10);
        var contents = new Recipients(protecting).Encrypt(Encoding.UTF8.GetBytes(key.ToSecretString()));
        return (new EncryptedIdentityFile(contents, passphrase), new Recipients(key.Recipient).Encrypt(Plaintext));
    }
}
