using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Unprotected OpenSSH keys that ssh-keygen would not write but OpenSSH and go-age read:
/// padding longer than a block (PuTTYgen pads 1–16 bytes), a comment ending in a byte that
/// looks like padding, and numbers with a redundant leading zero. BouncyCastle's reader refuses
/// them; AgeSharp then reads them with SSH.NET, as it reads protected keys. The fixtures are
/// <c>ed25519_plain</c> and <c>rsa_plain</c> rewritten; each one is checked with
/// <c>ssh-keygen -y</c>, and go-age decrypts with it.
/// </summary>
public class OpenSshKeyQuirksTests
{
    private static readonly byte[] Plaintext = "read as openssh reads it"u8.ToArray();

    public static TheoryData<string, string> Quirky => new()
    {
        { "ed25519_plain_padding_full_block", "ed25519_plain" },
        { "ed25519_plain_padding_29_bytes", "ed25519_plain" },
        { "ed25519_plain_comment_ends_in_01", "ed25519_plain" },
        { "rsa_plain_leading_zeros", "rsa_plain" },
    };

    [Theory]
    [MemberData(nameof(Quirky))]
    public void DecryptsWhatThePlainKeyWasEncryptedTo(string quirky, string plain)
    {
        var ciphertext = Encrypt(RecipientOf(SshIdentity.Parse(Key(plain))));

        Assert.Equal(Plaintext, Decrypt(ciphertext, SshIdentity.Parse(Key(quirky))));
    }

    [Theory]
    [MemberData(nameof(Quirky))]
    public void ItsRecipientIsThePlainKeys(string quirky, string plain)
    {
        var ciphertext = Encrypt(RecipientOf(SshIdentity.Parse(Key(quirky))));

        Assert.Equal(Plaintext, Decrypt(ciphertext, SshIdentity.Parse(Key(plain))));
    }

    [Theory]
    [MemberData(nameof(Quirky))]
    public void ThePassphraseOverloads_ReadItToo_WithoutAsking(string quirky, string plain)
    {
        var ciphertext = Encrypt(RecipientOf(SshIdentity.Parse(Key(plain))));

        Assert.Equal(Plaintext, Decrypt(ciphertext, SshIdentity.Parse(Key(quirky), NeverAsked)));
        Assert.Equal(Plaintext, Decrypt(ciphertext, SshIdentity.Parse(Key(quirky), Key(plain + ".pub"), NeverAsked)));
    }

    // What OpenSSH refuses stays refused: SSH.NET is only asked about what BouncyCastle
    // refuses, and is no laxer than OpenSSH about these. The message is BouncyCastle's.
    [Theory]
    [InlineData("ed25519_plain_padding_zeros", "trailing data")]
    [InlineData("ed25519_plain_check_mismatch", "check values")]
    [InlineData("ed25519_plain_two_keys", "multiple keys")]
    public void AKeyOpenSshRefuses_IsRefused(string key, string because)
    {
        var ex = Assert.Throws<FormatException>(() => SshIdentity.Parse(Key(key)));

        Assert.Contains(because, ex.Message);
    }

    // A key only SSH.NET reads gets the checks a key BouncyCastle reads gets: here n is not p·q
    // (q changed in a key with redundant leading zeros). Where SSH.NET hands RSA keys to the
    // platform at once (Linux, Windows), the platform refuses it and SSH.NET reads nothing, so
    // BouncyCastle's error is reported; on macOS SSH.NET reads it, and the RSA checks refuse it.
    [Fact]
    public void AKeyOnlySshNetReads_StillGetsTheRsaChecks()
    {
        var ex = Assert.Throws<FormatException>(() => SshIdentity.Parse(Key("rsa_plain_leading_zeros_unsound")));

        Assert.True(ex.Message.Contains("do not belong together") || ex.Message.Contains("Unnecessary leading bytes"), ex.Message);
    }

    [Fact]
    public void WhateverIsDoneToAQuirkyKey_OnlyFormatExceptionComesOut()
    {
        var original = KeyBlob("ed25519_plain_padding_29_bytes");
        var random = new Random(20261120);
        var attempts = int.Parse(Environment.GetEnvironmentVariable("AGESHARP_MUTATIONS") ?? "300");

        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var blob = (byte[])original.Clone();

            for (var flips = random.Next(1, 4); flips > 0; flips--)
                blob[random.Next(blob.Length)] ^= (byte)(1 << random.Next(8));

            try
            {
                SshIdentity.Parse(Pem(blob));
            }
            catch (FormatException)
            {
            }
        }
    }

    [SkippableFact]
    public void Interop_AgeEncryptsToThePublicKey_TheQuirkyKeyDecrypts()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");
        var ciphertext = AgeCli.Encrypt(Plaintext, false, Key("rsa_plain.pub").Trim());

        Assert.Equal(Plaintext, Decrypt(ciphertext, SshIdentity.Parse(Key("rsa_plain_leading_zeros"))));
    }

    private static char[]? NeverAsked() => throw new InvalidOperationException("the passphrase was asked for");

    private static string Key(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private static byte[] KeyBlob(string name) =>
        Convert.FromBase64String(string.Concat(Key(name).Split('\n').Where(line => line.Length > 0 && !line.StartsWith("-----", StringComparison.Ordinal))));

    private static string Pem(byte[] blob) =>
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + Convert.ToBase64String(blob, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n")
        + "\n-----END OPENSSH PRIVATE KEY-----\n";

    private static IRecipient RecipientOf(IIdentity identity) => identity switch
    {
        SshEd25519Identity ed25519 => ed25519.Recipient,
        SshRsaIdentity rsa => rsa.Recipient,
        _ => throw new InvalidOperationException(identity.GetType().Name),
    };

    private static byte[] Encrypt(IRecipient recipient)
    {
        using var output = new MemoryStream();
        new Recipients(recipient).Encrypt(new MemoryStream(Plaintext), output);
        return output.ToArray();
    }

    private static byte[] Decrypt(byte[] ciphertext, IIdentity identity)
    {
        using var output = new MemoryStream();
        new Identities(identity).Decrypt(new MemoryStream(ciphertext), output);
        return output.ToArray();
    }
}
