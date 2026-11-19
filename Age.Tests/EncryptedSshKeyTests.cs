using System.Text;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A passphrase-protected OpenSSH private key works as an identity. The fixtures were written by
/// ssh-keygen: each protected key is a re-encrypted copy of a plain one (passphrase "hunter2"),
/// so the plain key is the oracle for what the protected one must decrypt.
/// </summary>
public class EncryptedSshKeyTests
{
    private const string Passphrase = "hunter2";
    private static readonly byte[] Plaintext = "protected by an ssh key"u8.ToArray();

    public static TheoryData<string, string> ProtectedKeys => new()
    {
        { "ed25519_aes256ctr", "ed25519_plain" },
        { "ed25519_aes256cbc", "ed25519_plain" },
        { "ed25519_aes128ctr", "ed25519_plain" },
        { "ed25519_aes192ctr", "ed25519_plain" },
        { "ed25519_aes256gcm", "ed25519_plain" },
        { "ed25519_chacha20poly1305", "ed25519_plain" },
        { "ed25519_aes128cbc", "ed25519_plain" },
        { "ed25519_aes192cbc", "ed25519_plain" },
        { "ed25519_aes128gcm", "ed25519_plain" },
        { "ed25519_3descbc", "ed25519_plain" },
        { "ed25519_default_rounds", "ed25519_plain" },
        { "rsa_aes256ctr", "rsa_plain" },
        { "rsa_aes256gcm", "rsa_plain" },
    };

    [Theory]
    [MemberData(nameof(ProtectedKeys))]
    public void DecryptsWhatThePlainKeyWasEncryptedTo(string protectedKey, string plainKey)
    {
        var ciphertext = Encrypt(RecipientOf(AgeKeygen.ParseSshIdentity(Key(plainKey))));
        using var identity = EncryptedSshIdentity.Parse(Key(protectedKey), () => Passphrase);

        Assert.Equal(Plaintext, Decrypt(ciphertext, identity));
    }

    // Not ssh-keygen output: an ssh-keygen-style key re-encrypted with a private section that
    // ssh-keygen would not write but OpenSSH reads (checked with ssh-keygen -y). PuTTYgen pads
    // with a whole block where there is nothing to pad; no reader bounds the padding to one
    // block; and a comment may end in a byte that looks like padding.
    [Theory]
    [InlineData("ed25519_padding_full_block")]
    [InlineData("ed25519_padding_29_bytes")]
    [InlineData("ed25519_comment_ends_in_01")]
    public void ReadsWhatOpenSshReads_ThoughSshKeygenWouldNotWriteIt(string protectedKey)
    {
        using var identity = EncryptedSshIdentity.Parse(Key(protectedKey), () => Passphrase);

        Assert.Equal(Plaintext, Decrypt(Encrypt(identity.Recipient), identity));
    }

    [Theory]
    [MemberData(nameof(ProtectedKeys))]
    public void ItsRecipientIsThePlainKeysRecipient_WithoutThePassphrase(string protectedKey, string plainKey)
    {
        using var identity = EncryptedSshIdentity.Parse(Key(protectedKey), NeverAsked);

        var ciphertext = Encrypt(identity.Recipient);

        Assert.Equal(Plaintext, Decrypt(ciphertext, AgeKeygen.ParseSshIdentity(Key(plainKey))));
    }

    [Fact]
    public void AsksOnce_HoweverManyFilesItDecrypts()
    {
        var asked = 0;
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () => { asked++; return Passphrase; });
        var ciphertext = Encrypt(identity.Recipient);

        Decrypt(ciphertext, identity);
        Decrypt(ciphertext, identity);

        Assert.Equal(1, asked);
    }

    [Fact]
    public void DoesNotAsk_WhenTheFileIsForSomeoneElse()
    {
        using var someoneElse = X25519Identity.Generate();
        var ciphertext = Encrypt(someoneElse.Recipient);
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), NeverAsked);

        Assert.Throws<NoIdentityMatchException>(() => Decrypt(ciphertext, identity));
    }

    [Fact]
    public void DoesNotAsk_WhenTheFileIsForAnotherSshKey()
    {
        var ciphertext = Encrypt(RecipientOf(AgeKeygen.ParseSshIdentity(Key("rsa_plain"))));
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), NeverAsked);

        Assert.Throws<NoIdentityMatchException>(() => Decrypt(ciphertext, identity));
    }

    [Theory]
    [InlineData("ed25519_aes256ctr")]
    [InlineData("ed25519_aes256cbc")]
    [InlineData("ed25519_aes256gcm")]
    [InlineData("ed25519_chacha20poly1305")]
    [InlineData("rsa_aes256ctr")]
    public void AWrongPassphrase_IsReportedAsSuch_NotAsNoMatch(string protectedKey)
    {
        using var identity = EncryptedSshIdentity.Parse(Key(protectedKey), () => "hunter3");
        var ciphertext = Encrypt(identity.Recipient);

        var ex = Assert.Throws<AgeException>(() => Decrypt(ciphertext, identity));

        Assert.IsNotType<NoIdentityMatchException>(ex);
        Assert.Contains("passphrase", ex.Message);
    }

    [Fact]
    public void AnEmptyPassphrase_IsAWrongPassphrase()
    {
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () => "");

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("incorrect passphrase", ex.Message);
    }

    [Fact]
    public void AfterAWrongPassphrase_ItAsksAgain()
    {
        var answers = new Queue<string>(["hunter3", Passphrase]);
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), answers.Dequeue);
        var ciphertext = Encrypt(identity.Recipient);

        Assert.Throws<AgeException>(() => Decrypt(ciphertext, identity));

        Assert.Equal(Plaintext, Decrypt(ciphertext, identity));
    }

    [Fact]
    public void APlainKey_IsNotAnEncryptedSshIdentity()
    {
        Assert.Throws<FormatException>(() => EncryptedSshIdentity.Parse(Key("ed25519_plain"), NeverAsked));
    }

    [Fact]
    public void ParseSshIdentity_GivenAPassphraseSource_ReadsBothKinds()
    {
        var plain = AgeKeygen.ParseSshIdentity(Key("ed25519_plain"), NeverAsked);
        var protectedKey = AgeKeygen.ParseSshIdentity(Key("ed25519_aes256ctr"), () => Passphrase);

        Assert.IsType<SshEd25519Identity>(plain);
        Assert.IsType<EncryptedSshIdentity>(protectedKey);
        Assert.Equal(Plaintext, Decrypt(Encrypt(RecipientOf(plain)), protectedKey));
    }

    [Fact]
    public void ParseSshIdentity_WithoutAPassphraseSource_PointsAtTheOverload()
    {
        var ex = Assert.Throws<FormatException>(() => AgeKeygen.ParseSshIdentity(Key("ed25519_aes256ctr")));

        Assert.Contains("passphrase", ex.Message);
    }

    [Fact]
    public void ATruncatedKeyFile_IsRefused_WhereverItIsCut()
    {
        var blob = BlobOf(Key("ed25519_aes256ctr"));
        using var intact = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), NeverAsked);
        var ciphertext = Encrypt(intact.Recipient);

        for (var length = 0; length < blob.Length; length++)
        {
            var pem = Pem(blob[..length]);

            try
            {
                // Cut inside the encrypted section, the container still parses: the damage shows
                // only once the passphrase is used, and then as a failed decryption.
                using var identity = EncryptedSshIdentity.Parse(pem, () => Passphrase);
                Decrypt(ciphertext, identity);
                Assert.Fail($"a key file cut at {length} of {blob.Length} bytes decrypted");
            }
            catch (Exception ex) when (ex is FormatException or AgeException)
            {
            }
        }
    }

    [Fact]
    public void AKeyDamagedInItsEncryptedSection_IsRefused()
    {
        // CTR is unauthenticated, so a flipped bit decrypts to a flipped bit: here in the seed,
        // 60 bytes from the end, behind the public key copy, the comment and the padding.
        var blob = BlobOf(Key("ed25519_aes256ctr"));
        blob[^60] ^= 0x01;
        using var intact = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), NeverAsked);
        using var damaged = EncryptedSshIdentity.Parse(Pem(blob), () => Passphrase);

        var ex = Record.Exception(() => Decrypt(Encrypt(intact.Recipient), damaged));

        Assert.IsAssignableFrom<AgeException>(ex);
        Assert.IsNotType<NoIdentityMatchException>(ex);
    }

    // An RSA key file states its private exponent, its primes and a CRT coefficient one by one,
    // and nothing in the format ties them to each other or to the public key. Forty bytes from
    // the end, behind the comment and the padding, is the second prime.
    [Fact]
    public void AnRsaKeyWhosePartsDoNotBelongTogether_IsRefused_ProtectedOrNot()
    {
        var plain = BlobOf(Key("rsa_plain"));
        plain[^40] ^= 0x01;
        var protectedBlob = BlobOf(Key("rsa_aes256ctr"));
        protectedBlob[^40] ^= 0x01;
        using var damaged = EncryptedSshIdentity.Parse(Pem(protectedBlob), () => Passphrase);

        var whenPlain = Assert.Throws<FormatException>(() => AgeKeygen.ParseSshIdentity(Pem(plain)));
        var whenProtected = Assert.Throws<AgeException>(() => Decrypt(Encrypt(damaged.Recipient), damaged));

        Assert.Contains("do not belong together", whenPlain.Message);
        Assert.Matches(RefusedAsAnImpossibleRsaKey, whenProtected.Message);
    }

    // Which check refuses a protected RSA key whose numbers cannot be a key depends on the
    // platform: on Linux and Windows (seen in CI) SSH.NET refuses it first; on macOS it does
    // not, and AgeSharp's own check does.
    private const string RefusedAsAnImpossibleRsaKey = "do not belong together|unreadable SSH private key";

    // Under CTR anyone can flip a chosen bit of the key without the passphrase. This one is the
    // lowest bit of the public exponent, which the private section repeats after the modulus.
    [Fact]
    public void AnRsaKeyWithItsPublicExponentMadeEven_IsRefusedAsAnAgeError()
    {
        var blob = BlobOf(Key("rsa_aes256ctr"));
        var offset = PublicKeyOffset(blob);
        var publicKey = ReadField(blob, ref offset);
        var position = 0;
        ReadField(publicKey, ref position);
        var exponentLength = ReadField(publicKey, ref position).Length;
        var modulusLength = ReadField(publicKey, ref position).Length;
        var sectionStart = offset + 4;
        var lastByteOfExponent = sectionStart + 8 + (4 + "ssh-rsa".Length) + (4 + modulusLength) + (4 + exponentLength) - 1;
        blob[lastByteOfExponent] ^= 0x01;
        using var damaged = EncryptedSshIdentity.Parse(Pem(blob), () => Passphrase);

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(damaged.Recipient), damaged));

        Assert.Matches("incorrect public exponent|unreadable SSH private key", ex.Message);
    }

    [Fact]
    public void DisposedByItsOwnPassphraseSource_ItDoesNotUnwrap()
    {
        EncryptedSshIdentity? identity = null;
        identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () =>
        {
            identity!.Dispose();
            return Passphrase;
        });
        var ciphertext = Encrypt(identity.Recipient);

        Assert.Throws<ObjectDisposedException>(() => Decrypt(ciphertext, identity));
    }

    // AGESHARP_MUTATIONS raises the number of damaged files tried, for a longer hunt.
    [Theory]
    [InlineData("ed25519_aes256ctr")]
    [InlineData("rsa_aes256ctr")]
    public void WhateverIsDoneToAKeyFile_OnlyTheDocumentedErrorsComeOut(string protectedKey)
    {
        var original = BlobOf(Key(protectedKey));
        using var intact = EncryptedSshIdentity.Parse(Key(protectedKey), NeverAsked);
        var ciphertext = Encrypt(intact.Recipient);
        var random = new Random(20261117);
        var attempts = int.Parse(Environment.GetEnvironmentVariable("AGESHARP_MUTATIONS") ?? "200");

        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var blob = (byte[])original.Clone();

            for (var flips = random.Next(1, 4); flips > 0; flips--)
                blob[random.Next(blob.Length)] ^= (byte)(1 << random.Next(8));

            // A flip that raises the round count would only make this slow, not wrong.
            if (RoundsOf(blob) > 2)
                continue;

            try
            {
                using var identity = EncryptedSshIdentity.Parse(Pem(blob), () => Passphrase);
                Decrypt(ciphertext, identity);
            }
            catch (Exception ex) when (ex is FormatException or AgeException)
            {
            }
        }
    }

    // The public key is the only part read before the passphrase, and nothing ties it to the
    // encrypted part: here an ECDSA key file presents an ed25519 public key. It is accepted as an
    // ed25519 identity until it is unlocked, and refused then.
    [Fact]
    public void AnEd25519PublicKeyInFrontOfAnotherKindOfKey_IsRefusedOnceUnlocked()
    {
        var ecdsa = BlobOf(Key("ecdsa_aes256ctr"));
        var ed25519 = BlobOf(Key("ed25519_aes256ctr"));
        var spliced = ReplacePublicKey(ecdsa, PublicKeyField(ed25519));
        using var identity = EncryptedSshIdentity.Parse(Pem(spliced), () => Passphrase);

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("unsupported SSH key type", ex.Message);
    }

    [Fact]
    public void APublicKeyThatIsNotThePrivateKeys_IsRefused()
    {
        // The container names its public key in the clear; swap in another key's, and the file
        // claims to decrypt for a recipient its private key does not belong to.
        var ed25519 = BlobOf(Key("ed25519_aes256ctr"));
        var other = BlobOf(Key("ed25519_plain_other"));
        var swapped = SwapPublicKey(ed25519, other);
        using var identity = EncryptedSshIdentity.Parse(Pem(swapped), () => Passphrase);

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("mismatched", ex.Message);
    }

    [Fact]
    public void APassphraseSourceThatFails_IsReportedAsAnAgeError()
    {
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () => throw new IOException("no terminal"));

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains("no terminal", ex.Message);
    }

    // A passphrase source that decrypts with the identity it is answering for would recurse, or
    // leave a second unlocked key that nothing clears. It is refused instead.
    [Fact]
    public void APassphraseSourceThatDecryptsWithItsOwnIdentity_IsRefused()
    {
        EncryptedSshIdentity? identity = null;
        byte[]? ciphertext = null;
        Exception? inner = null;
        identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () =>
        {
            inner = Record.Exception(() => Decrypt(ciphertext!, identity!));
            return Passphrase;
        });
        ciphertext = Encrypt(identity.Recipient);

        using (identity)
            Assert.Equal(Plaintext, Decrypt(ciphertext, identity));

        var refused = Assert.IsType<AgeException>(inner);
        Assert.Contains("passphrase source", refused.Message);
    }

    // A prompt the user closes is not an error, and the caller should be able to tell.
    [Fact]
    public void APassphraseSourceThatIsCancelled_CancelsTheDecryption()
    {
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () => throw new OperationCanceledException());

        Assert.ThrowsAny<OperationCanceledException>(() => Decrypt(Encrypt(identity.Recipient), identity));
    }

    [Fact]
    public void OnceDisposed_ItNoLongerUnwraps()
    {
        var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () => Passphrase);
        var ciphertext = Encrypt(identity.Recipient);
        Decrypt(ciphertext, identity);

        identity.Dispose();
        identity.Dispose();

        Assert.Throws<ObjectDisposedException>(() => Decrypt(ciphertext, identity));
    }

    [Fact]
    public void AProtectedKeyOfATypeAgeDoesNotUse_IsRefused()
    {
        var ex = Assert.Throws<FormatException>(() => EncryptedSshIdentity.Parse(Key("ecdsa_aes256ctr"), NeverAsked));

        Assert.Contains("unsupported SSH key type", ex.Message);
    }

    [Fact]
    public void AKeyFileHoldingMoreThanOneKey_IsRefusedWhenRead()
    {
        var blob = SetKeyCount(BlobOf(Key("ed25519_aes256ctr")), 2);

        var ex = Assert.Throws<FormatException>(() => EncryptedSshIdentity.Parse(Pem(blob), NeverAsked));

        Assert.Contains("exactly one key", ex.Message);
    }

    // What this library cannot decrypt is said once a file is addressed to the key, before the
    // passphrase is asked for, and not when the key file is read: as in go-age, a key that is
    // never needed does not stop anything. "aes256-ctr" is ten bytes, as are its replacements.
    public static TheoryData<string, Func<byte[], byte[]>> KeysThatCannotBeDecrypted => new()
    {
        { "unsupported SSH private key KDF", blob => Replace(blob, "bcrypt"u8, "scrypt"u8) },
        { "more than the maximum of 2048", blob => SetRounds(blob, 2049) },
        { "malformed bcrypt options", blob => SetRounds(blob, 0) },
        { "unsupported SSH private key cipher: aes999-ctr", blob => Replace(blob, "aes256-ctr"u8, "aes999-ctr"u8) },
        { "unsupported SSH private key cipher: ?[2Jevil!!", blob => Replace(blob, "aes256-ctr"u8, "\u001b[2Jevil!!"u8) },
    };

    [Theory]
    [MemberData(nameof(KeysThatCannotBeDecrypted))]
    public void AKeyThatCannotBeDecrypted_IsReadButRefusedWhenAFileMatches_WithoutAsking(string because, Func<byte[], byte[]> change)
    {
        var blob = change(BlobOf(Key("ed25519_aes256ctr")));
        using var identity = EncryptedSshIdentity.Parse(Pem(blob), NeverAsked);

        var ex = Assert.Throws<AgeException>(() => Decrypt(Encrypt(identity.Recipient), identity));

        Assert.Contains(because, ex.Message);
        Assert.DoesNotContain('\u001b', ex.Message);
    }

    [Fact]
    public void AKeyThatCannotBeDecrypted_DoesNotStopAnotherIdentityFromDecrypting()
    {
        var overTheCap = SetRounds(BlobOf(Key("ed25519_aes256ctr")), 4096);
        using var cannot = EncryptedSshIdentity.Parse(Pem(overTheCap), NeverAsked);
        using var can = X25519Identity.Generate();
        var ciphertext = Encrypt(can.Recipient);

        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(new MemoryStream(ciphertext), output, cannot, can);

        Assert.Equal(Plaintext, output.ToArray());
    }

    // In a browser SSH.NET cannot decrypt these, and the identity says so instead of asking for
    // a passphrase it cannot use. Only what was checked there by hand is let through: ed25519
    // keys with aes256-gcm or chacha20-poly1305. Here, only which is which.
    [Theory]
    [InlineData("ssh-ed25519", "aes128-ctr", true)]
    [InlineData("ssh-ed25519", "aes256-ctr", true)]
    [InlineData("ssh-ed25519", "aes256-cbc", true)]
    [InlineData("ssh-ed25519", "3des-cbc", true)]
    [InlineData("ssh-ed25519", "aes128-gcm@openssh.com", true)]
    [InlineData("ssh-ed25519", "aes256-gcm@openssh.com", false)]
    [InlineData("ssh-ed25519", "chacha20-poly1305@openssh.com", false)]
    [InlineData("ssh-rsa", "aes256-ctr", true)]
    [InlineData("ssh-rsa", "aes256-gcm@openssh.com", true)]
    [InlineData("ssh-rsa", "chacha20-poly1305@openssh.com", true)]
    public void WhichKeysTheBrowserCannotDecrypt(string keyType, string cipher, bool refused) =>
        Assert.Equal(refused, Age.Crypto.ProtectedOpenSshKey.WhyItCannotBeDecryptedInTheBrowser(keyType, cipher) is not null);

    [SkippableFact]
    public void Interop_AgeEncryptsToThePublicKey_TheProtectedKeyDecrypts()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");
        var ciphertext = AgeCli.Encrypt(Plaintext, false, Key("ed25519_plain.pub").Trim());
        using var identity = EncryptedSshIdentity.Parse(Key("ed25519_aes256ctr"), () => Passphrase);

        Assert.Equal(Plaintext, Decrypt(ciphertext, identity));
    }

    private static string NeverAsked() => throw new InvalidOperationException("the passphrase was asked for");

    private static string Key(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private static IRecipient RecipientOf(IIdentity identity) => identity switch
    {
        SshEd25519Identity ed25519 => ed25519.Recipient,
        SshRsaIdentity rsa => rsa.Recipient,
        _ => throw new InvalidOperationException(identity.GetType().Name),
    };

    private static byte[] Encrypt(IRecipient recipient)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(Plaintext), output, recipient);
        return output.ToArray();
    }

    private static byte[] Decrypt(byte[] ciphertext, IIdentity identity)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(new MemoryStream(ciphertext), output, identity);
        return output.ToArray();
    }

    private static byte[] BlobOf(string pem) =>
        Convert.FromBase64String(string.Concat(pem.Split('\n').Where(line => !line.StartsWith("-----"))));

    private static string Pem(byte[] blob) =>
        new StringBuilder()
            .AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----")
            .AppendLine(Convert.ToBase64String(blob, Base64FormattingOptions.InsertLineBreaks))
            .AppendLine("-----END OPENSSH PRIVATE KEY-----")
            .ToString();

    // Both blobs hold an ed25519 public key, so the field sits at the same offset and length in
    // each: after the magic, the cipher, the KDF and its options, and the key count.
    private static byte[] SwapPublicKey(byte[] into, byte[] from)
    {
        const int publicKeyLength = 4 + 51;
        var result = (byte[])into.Clone();
        from.AsSpan(PublicKeyOffset(from), publicKeyLength).CopyTo(result.AsSpan(PublicKeyOffset(into)));
        return result;
    }

    // Reads the length-prefixed field at an offset, and moves the offset past it.
    private static byte[] ReadField(byte[] from, ref int offset)
    {
        var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(from.AsSpan(offset));
        var field = from.AsSpan(offset + 4, length).ToArray();
        offset += 4 + length;
        return field;
    }

    private static byte[] Replace(byte[] blob, ReadOnlySpan<byte> find, ReadOnlySpan<byte> with)
    {
        var result = (byte[])blob.Clone();
        with.CopyTo(result.AsSpan(result.AsSpan().IndexOf(find)));
        return result;
    }

    private static byte[] SetKeyCount(byte[] blob, uint count)
    {
        var result = (byte[])blob.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(PublicKeyOffset(blob) - 4), count);
        return result;
    }

    private static byte[] SetRounds(byte[] blob, uint rounds)
    {
        var result = (byte[])blob.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(PublicKeyOffset(blob) - 8), rounds);
        return result;
    }

    private static uint RoundsOf(byte[] blob)
    {
        try
        {
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(PublicKeyOffset(blob) - 8));
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException)
        {
            return uint.MaxValue;
        }
    }

    // The public key field, length prefix included.
    private static byte[] PublicKeyField(byte[] blob)
    {
        var offset = PublicKeyOffset(blob);
        var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset));
        return blob.AsSpan(offset, 4 + length).ToArray();
    }

    private static byte[] ReplacePublicKey(byte[] blob, byte[] field)
    {
        var offset = PublicKeyOffset(blob);
        var oldLength = 4 + (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset));
        return [.. blob.AsSpan(0, offset), .. field, .. blob.AsSpan(offset + oldLength)];
    }

    private static int PublicKeyOffset(byte[] blob)
    {
        var offset = "openssh-key-v1\0".Length;

        for (var field = 0; field < 3; field++)
            offset += 4 + (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset));

        return offset + 4;
    }
}
