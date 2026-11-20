using System.Security.Cryptography;
using System.Text;
using AgeSharp;
using Org.BouncyCastle.Crypto.Generators;
using Xunit;

namespace Age.Tests;

/// <summary>
/// An empty passphrase protects nothing, so it cannot encrypt — go-age refuses it too. It can
/// still decrypt: earlier versions accepted it, and files they made must stay readable.
/// </summary>
public class ScryptPassphraseTests
{
    [Fact]
    public void NullPassphrase_IsRejectedAtConstruction() =>
        Assert.Throws<ArgumentNullException>(() => new Passphrase(null!));

    [Fact]
    public void EmptyPassphrase_CannotEncrypt()
    {
        using var output = new MemoryStream();

        var ex = Assert.Throws<ArgumentException>(() =>
            new Recipients(new Passphrase("", workFactor: 10)).Encrypt(new MemoryStream("plaintext"u8.ToArray()), output));

        Assert.Contains("empty", ex.Message);
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public void EmptyPassphrase_StillDecryptsAFileMadeWithOne()
    {
        var plaintext = "made by an earlier AgeSharp"u8.ToArray();
        using var file = new MemoryStream();
        new Recipients(new EmptyPassphraseScrypt()).Encrypt(new MemoryStream(plaintext), file);
        file.Position = 0;

        using var output = new MemoryStream();
        new Identities(new Passphrase("")).Decrypt(file, output);

        Assert.Equal(plaintext, output.ToArray());
    }

    /// <summary>
    /// The scrypt stanza an empty passphrase produces, built from age.md rather than through
    /// Passphrase, which no longer makes one.
    /// </summary>
    private sealed class EmptyPassphraseScrypt : IRecipient
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
        {
            const int workFactor = 10;
            var salt = RandomNumberGenerator.GetBytes(16);
            byte[] scryptSalt = [.. "age-encryption.org/v1/scrypt"u8, .. salt];
            var key = SCrypt.Generate([], scryptSalt, 1 << workFactor, 8, 1, 32);

            var body = new byte[fileKey.Length + 16];
            using (var aead = new ChaCha20Poly1305(key))
                aead.Encrypt(new byte[12], fileKey, body.AsSpan(0, fileKey.Length), body.AsSpan(fileKey.Length));

            var saltArg = Convert.ToBase64String(salt).TrimEnd('=');
            return [new Stanza("scrypt", [saltArg, workFactor.ToString(System.Globalization.CultureInfo.InvariantCulture)], body)];
        }
    }
}
