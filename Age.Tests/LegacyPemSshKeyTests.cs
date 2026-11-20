using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A passphrase-protected ssh-rsa key in the legacy PEM format (<c>BEGIN RSA PRIVATE KEY</c> with
/// <c>Proc-Type: 4,ENCRYPTED</c>), as ssh-keygen wrote by default before OpenSSH 7.8 and still
/// writes with <c>-m PEM</c>. Nothing in it is in the clear, so, as in go-age, its public key
/// comes from the <c>.pub</c> file. The fixtures are re-encryptions of <c>rsa_plain</c>
/// (passphrase "hunter2"): <c>rsa_legacy_pem</c> by ssh-keygen -m PEM, the others by openssl.
/// </summary>
public class LegacyPemSshKeyTests
{
    private const string Passphrase = "hunter2";
    private static readonly byte[] Plaintext = "protected by a legacy pem key"u8.ToArray();

    public static TheoryData<string> LegacyKeys => new()
    {
        "rsa_legacy_pem", // AES-128-CBC, ssh-keygen -m PEM
        "rsa_legacy_pem_aes192",
        "rsa_legacy_pem_aes256",
        "rsa_legacy_pem_3des",
    };

    [Theory]
    [MemberData(nameof(LegacyKeys))]
    public void DecryptsWhatThePlainKeyWasEncryptedTo(string legacyKey)
    {
        var ciphertext = Encrypt(PlainRecipient());
        using var identity = ParseEncrypted(legacyKey, "rsa_plain.pub", () => Passphrase);

        Assert.Equal(Plaintext, Decrypt(ciphertext, identity));
    }

    [Theory]
    [MemberData(nameof(LegacyKeys))]
    public void ItsRecipientIsThePublicKeyFiles_WithoutThePassphrase(string legacyKey)
    {
        using var identity = ParseEncrypted(legacyKey, "rsa_plain.pub", NeverAsked);

        var ciphertext = Encrypt(identity.Recipient);

        Assert.Equal(Plaintext, Decrypt(ciphertext, SshIdentity.Parse(Key("rsa_plain"))));
    }

    [Fact]
    public void DoesNotAsk_WhenTheFileIsForSomeoneElse()
    {
        using var someoneElse = X25519Identity.Generate();
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", NeverAsked);

        Assert.Throws<NoIdentityMatchException>(() => Decrypt(Encrypt(someoneElse.Recipient), identity));
    }

    [Fact]
    public void DoesNotAsk_WhenTheFileIsForAnotherSshKey()
    {
        var ciphertext = Encrypt(Recipients.ParseOne(Key("rsa_other.pub")));
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", NeverAsked);

        Assert.Throws<NoIdentityMatchException>(() => Decrypt(ciphertext, identity));
    }

    [Fact]
    public void AsksOnce_HoweverManyFilesItDecrypts()
    {
        var asked = 0;
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", () => { asked++; return Passphrase; });
        var ciphertext = Encrypt(identity.Recipient);

        Decrypt(ciphertext, identity);
        Decrypt(ciphertext, identity);

        Assert.Equal(1, asked);
    }

    [Theory]
    [MemberData(nameof(LegacyKeys))]
    public void AWrongPassphrase_IsReportedAsSuch_NotAsNoMatch(string legacyKey)
    {
        using var identity = ParseEncrypted(legacyKey, "rsa_plain.pub", () => "hunter3");

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.IsNotType<NoIdentityMatchException>(ex);
        Assert.Contains("incorrect passphrase", ex.Message);
    }

    // The format has no check of its own: a wrong passphrase is noticed by the CBC padding,
    // which a wrong key still gets right about once in 256 tries, and then by the decrypted
    // bytes not being a key. Either way it is a wrong passphrase, as in Go.
    [Fact]
    public void EveryWrongPassphrase_IsAWrongPassphrase_EvenWhenThePaddingHappensToBeValid()
    {
        var attempt = 0;
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", () => $"wrong {attempt++}");
        var ciphertext = Encrypt(identity.Recipient);

        for (var i = 0; i < 1000; i++)
        {
            var ex = Assert.Throws<AgeException>(() => Decrypt(ciphertext, identity));
            Assert.Contains("incorrect passphrase", ex.Message);
        }
    }

    [Fact]
    public void AnEmptyPassphrase_IsAWrongPassphrase()
    {
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", () => "");

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("incorrect passphrase", ex.Message);
    }

    [Fact]
    public void AfterAWrongPassphrase_ItAsksAgain()
    {
        var answers = new Queue<string>(["hunter3", Passphrase]);
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", answers.Dequeue);
        var ciphertext = Encrypt(identity.Recipient);

        Assert.Throws<AgeException>(() => Decrypt(ciphertext, identity));

        Assert.Equal(Plaintext, Decrypt(ciphertext, identity));
    }

    // The .pub file is trusted for which stanzas are this key's, and checked against the
    // private key once it is decrypted: the other way round, a key file would answer for a
    // recipient whose private key it does not hold.
    [Fact]
    public void APublicKeyFileThatIsNotTheKeys_IsRefusedOnceUnlocked()
    {
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_other.pub", () => Passphrase);

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("mismatched", ex.Message);
    }

    [Fact]
    public void APublicKeyFileOfAnotherType_IsRefused()
    {
        var ex = Assert.Throws<FormatException>(() => Parse("rsa_legacy_pem", "ed25519_plain.pub", NeverAsked));

        Assert.Contains("ssh-rsa", ex.Message);
    }

    [Fact]
    public void APublicKeyFileThatIsNotAPublicKey_IsRefused()
    {
        Assert.Throws<FormatException>(() =>
            SshIdentity.Parse(Key("rsa_legacy_pem"), "not a public key", NeverAsked));
    }

    // go-age reads single-DES keys too; SSH.NET does not, and openssl no longer writes them
    // without its legacy provider. The key is read, and refused when a file is for it, before
    // the passphrase is asked for.
    [Fact]
    public void ASingleDesKey_IsReadButRefusedWhenAFileMatches_WithoutAsking()
    {
        using var identity = ParseEncrypted("rsa_legacy_pem_des", "rsa_plain.pub", NeverAsked);

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("DES-CBC", ex.Message);
        Assert.Contains("ssh-keygen -p", ex.Message);
    }

    [Theory]
    [InlineData("AES-128-CFB", "AES-128-CFB")]
    [InlineData("\u001b[2Jevil", "?[2Jevil")]
    public void AnUnknownCipher_IsReadButRefusedWhenAFileMatches_WithoutAsking(string cipher, string shown)
    {
        var pem = Key("rsa_legacy_pem").Replace("DEK-Info: AES-128-CBC,", $"DEK-Info: {cipher},");
        using var identity = Assert.IsType<EncryptedSshIdentity>(SshIdentity.Parse(pem, Key("rsa_plain.pub"), NeverAsked));

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(Recipients.ParseOne(Key("rsa_plain.pub"))), identity));

        Assert.Contains(shown, ex.Message);
        Assert.DoesNotContain('\u001b', ex.Message);
    }

    public static TheoryData<string, Func<string, string>> MalformedHeaders => new()
    {
        { "no DEK-Info", pem => RemoveLine(pem, "DEK-Info:") },
        { "no Proc-Type", pem => RemoveLine(pem, "Proc-Type:") },
        { "IV not hex", pem => ReplaceIv(pem, iv => "ZZ" + iv[2..]) },
        { "IV too short", pem => ReplaceIv(pem, iv => iv[2..]) },
        { "IV too long", pem => ReplaceIv(pem, iv => iv + "00") },
        { "body not base64", pem => pem.Replace("-----END", "!!!!\n-----END") },
        { "body not whole blocks", pem => TruncateBody(pem, 3) },
        { "no body", pem => TruncateBody(pem, int.MaxValue) },
        { "a second key after it", pem => pem + pem },
    };

    [Theory]
    [MemberData(nameof(MalformedHeaders))]
    public void AMalformedKeyFile_IsRefusedWhenRead(string because, Func<string, string> change)
    {
        var pem = change(Key("rsa_legacy_pem"));

        var ex = Assert.Throws<FormatException>(() => SshIdentity.Parse(pem, Key("rsa_plain.pub"), NeverAsked));

        Assert.False(string.IsNullOrEmpty(ex.Message), because);
    }

    [Fact]
    public void AKeyDamagedInItsEncryptedSection_IsAWrongPassphrase()
    {
        // Indistinguishable from a wrong passphrase: the format authenticates nothing.
        var pem = DamageBody(Key("rsa_legacy_pem"));
        using var identity = Assert.IsType<EncryptedSshIdentity>(SshIdentity.Parse(pem, Key("rsa_plain.pub"), () => Passphrase));

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(Recipients.ParseOne(Key("rsa_plain.pub"))), identity));

        Assert.Contains("incorrect passphrase", ex.Message);
    }

    [Fact]
    public void WhateverIsDoneToAKeyFile_OnlyTheDocumentedErrorsComeOut()
    {
        var original = Encoding.ASCII.GetBytes(Key("rsa_legacy_pem"));
        var ciphertext = Encrypt(PlainRecipient());
        var random = new Random(20261119);
        var attempts = int.Parse(Environment.GetEnvironmentVariable("AGESHARP_MUTATIONS") ?? "200");

        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var text = (byte[])original.Clone();

            for (var flips = random.Next(1, 4); flips > 0; flips--)
                text[random.Next(text.Length)] ^= (byte)(1 << random.Next(7));

            try
            {
                var identity = SshIdentity.Parse(Encoding.ASCII.GetString(text), Key("rsa_plain.pub"), () => Passphrase);
                Decrypt(ciphertext, identity);
                (identity as IDisposable)?.Dispose();
            }
            catch (Exception ex) when (ex is FormatException or AgeException)
            {
            }
        }
    }

    // Encrypted PKCS#8 has no public key in the clear either; go-age does not read it, and
    // neither does AgeSharp.
    [Fact]
    public void EncryptedPkcs8_IsRefused_WithTheWayOut()
    {
        var ex = Assert.Throws<FormatException>(() => Parse("rsa_pkcs8_encrypted", "rsa_plain.pub", NeverAsked));

        Assert.Contains("ssh-keygen -p", ex.Message);
    }

    [Fact]
    public void WithoutThePublicKeyFile_TheErrorPointsAtTheOverloadThatTakesIt()
    {
        var ex = Assert.Throws<FormatException>(() => SshIdentity.Parse(Key("rsa_legacy_pem"), NeverAsked));

        Assert.Contains(".pub", ex.Message);
        Assert.Contains("ssh-keygen -p", ex.Message);
    }

    [Fact]
    public void WithoutAPassphraseSource_TheErrorSaysItIsPassphraseProtected()
    {
        var ex = Assert.Throws<FormatException>(() => SshIdentity.Parse(Key("rsa_legacy_pem")));

        Assert.Contains("passphrase", ex.Message);
    }

    // The overload takes any SSH private key, as go-age's command does: the .pub file is then
    // checked against the public key the key file carries.
    [Theory]
    [InlineData("rsa_aes256ctr")]
    [InlineData("rsa_plain")]
    public void AnOpenSshKeyFile_IsReadToo_AndItsPublicKeyFileMustMatchIt(string keyFile)
    {
        var identity = Parse(keyFile, "rsa_plain.pub", () => Passphrase);
        Assert.Equal(Plaintext, Decrypt(Encrypt(PlainRecipient()), identity));
        (identity as IDisposable)?.Dispose();

        var ex = Assert.Throws<FormatException>(() => Parse(keyFile, "rsa_other.pub", NeverAsked));
        Assert.Contains("does not belong", ex.Message);
    }

    [Fact]
    public void AnUnprotectedKey_IsNeverAskedForAPassphrase()
    {
        var identity = Parse("rsa_plain", "rsa_plain.pub", NeverAsked);

        Assert.IsType<SshRsaIdentity>(identity);
        Assert.Equal(Plaintext, Decrypt(Encrypt(PlainRecipient()), identity));
    }

    [Fact]
    public void InTheBrowser_ALegacyKeyIsRefused()
    {
        Assert.NotNull(AgeSharp.Crypto.LegacyPemSshKey.WhyItCannotBeDecryptedInTheBrowser());
    }

    [SkippableFact]
    public void Interop_AgeEncryptsToThePublicKey_TheLegacyKeyDecrypts()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");
        var ciphertext = AgeCli.Encrypt(Plaintext, false, Key("rsa_plain.pub").Trim());
        using var identity = ParseEncrypted("rsa_legacy_pem", "rsa_plain.pub", () => Passphrase);

        Assert.Equal(Plaintext, Decrypt(ciphertext, identity));
    }

    private static IIdentity Parse(string keyFile, string publicKeyFile, Func<string> passphrase) =>
        SshIdentity.Parse(Key(keyFile), Key(publicKeyFile), passphrase);

    private static EncryptedSshIdentity ParseEncrypted(string keyFile, string publicKeyFile, Func<string> passphrase) =>
        Assert.IsType<EncryptedSshIdentity>(Parse(keyFile, publicKeyFile, passphrase));

    private static string NeverAsked() => throw new InvalidOperationException("the passphrase was asked for");

    private static string Key(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private static IRecipient PlainRecipient() => Recipients.ParseOne(Key("rsa_plain.pub"));

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

    private static string RemoveLine(string pem, string prefix) =>
        string.Join('\n', pem.Split('\n').Where(line => !line.StartsWith(prefix, StringComparison.Ordinal)));

    private static string ReplaceIv(string pem, Func<string, string> change) =>
        string.Join('\n', pem.Split('\n').Select(line =>
        {
            if (!line.StartsWith("DEK-Info:", StringComparison.Ordinal))
                return line;

            var comma = line.IndexOf(',');
            return line[..(comma + 1)] + change(line[(comma + 1)..].Trim());
        }));

    private static (string Head, byte[] Body, string Tail) Split(string pem)
    {
        var lines = pem.Split('\n');
        var blank = Array.IndexOf(lines, "");
        var end = Array.FindIndex(lines, line => line.StartsWith("-----END", StringComparison.Ordinal));
        return (string.Join('\n', lines[..(blank + 1)]), Convert.FromBase64String(string.Concat(lines[(blank + 1)..end])),
            string.Join('\n', lines[end..]));
    }

    private static string Join(string head, byte[] body, string tail) =>
        head + "\n" + Convert.ToBase64String(body, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n") + "\n" + tail;

    private static string TruncateBody(string pem, int bytes)
    {
        var (head, body, tail) = Split(pem);
        var keep = body[..Math.Max(0, body.Length - bytes)];
        return keep.Length == 0 ? head + "\n" + tail : Join(head, keep, tail);
    }

    private static string DamageBody(string pem)
    {
        // The last byte: the last block, and with it the CBC padding, no longer decrypts.
        var (head, body, tail) = Split(pem);
        body[^1] ^= 0x01;
        return Join(head, body, tail);
    }
}
