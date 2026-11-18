using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit;

namespace Age.Tests;

/// <summary>
/// SSH key parsing reports every malformed input as <see cref="FormatException"/>, as documented.
/// Other exception types leaked out of BouncyCastle and out of casts that trusted the
/// authorized_keys type field, past callers that handle FormatException.
/// </summary>
public class SshParsingErrorTests
{
    private static readonly byte[] Ed25519Wire = OpenSshPublicKeyUtilities.EncodePublicKey(
        new Ed25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey());

    private static readonly AsymmetricCipherKeyPair Rsa1024 = GenerateRsa(1024);
    private static readonly AsymmetricCipherKeyPair Rsa2048 = GenerateRsa(2048);

    public static TheoryData<string, string> MalformedPublicKeys => new()
    {
        { "ed25519 type, rsa key", $"ssh-ed25519 {Wire(Rsa2048)}" },
        { "rsa type, ed25519 key", $"ssh-rsa {Convert.ToBase64String(Ed25519Wire)}" },
        { "ed25519 type, ecdsa key", $"ssh-ed25519 {Wire(EcdsaP256())}" },
        { "rsa under 2048 bits", $"ssh-rsa {Wire(Rsa1024)}" },
        { "garbage key data", "ssh-ed25519 AAAA" },
        { "truncated key data", $"ssh-ed25519 {Convert.ToBase64String(Ed25519Wire[..^10])}" },
    };

    [Theory]
    [MemberData(nameof(MalformedPublicKeys))]
    public void ParseSshRecipient_Malformed_ThrowsFormatException(string why, string line)
    {
        _ = why;
        Assert.Throws<FormatException>(() => AgeKeygen.ParseSshRecipient(line));
    }

    [Fact]
    public void RsaRecipientParse_UnderMinimumSize_ThrowsFormatException() =>
        Assert.Throws<FormatException>(() => Age.Recipients.SshRsaRecipient.Parse($"ssh-rsa {Wire(Rsa1024)}"));

    [Fact]
    public void Ed25519RecipientParse_RsaKeyData_ThrowsFormatException() =>
        Assert.Throws<FormatException>(() => Age.Recipients.SshEd25519Recipient.Parse($"ssh-ed25519 {Wire(Rsa2048)}"));

    public static TheoryData<string, string> PassphraseProtectedKeys => new()
    {
        { "openssh", PassphraseProtectedOpenSsh() },
        { "pkcs#1 pem", EncryptedPem(new MiscPemGenerator(Rsa1024.Private, "AES-128-CBC", "pw".ToCharArray(), new SecureRandom())) },
        { "pkcs#8 pem", EncryptedPem(new Pkcs8Generator(Rsa1024.Private, Pkcs8Generator.PbeWithShaAnd3KeyTripleDesCbc) { Password = "pw".ToCharArray() }) },
    };

    [Theory]
    [MemberData(nameof(PassphraseProtectedKeys))]
    public void ParseSshIdentity_PassphraseProtected_SaysSo(string format, string pem)
    {
        _ = format;
        var ex = Assert.Throws<FormatException>(() => AgeKeygen.ParseSshIdentity(pem));
        Assert.Contains("passphrase-protected", ex.Message);
    }

    public static TheoryData<string, string> MalformedPrivateKeys => new()
    {
        { "pkcs#1 body not a key", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n" },
        { "openssh body not a key", Pem("OPENSSH PRIVATE KEY", "openssh-key-v1\0 not really"u8.ToArray()) },
        { "openssh body truncated", Pem("OPENSSH PRIVATE KEY", "openssh-key-v1\0"u8.ToArray()) },
    };

    [Theory]
    [MemberData(nameof(MalformedPrivateKeys))]
    public void ParseSshIdentity_Malformed_ThrowsFormatException(string why, string pem)
    {
        _ = why;
        Assert.Throws<FormatException>(() => AgeKeygen.ParseSshIdentity(pem));
    }

    // The fields of an RSA private key, in the order the OpenSSH format states them.
    private const int N = 0, E = 1, D = 2, Iqmp = 3, P = 4, Q = 5;

    public static TheoryData<string, Func<System.Numerics.BigInteger[], System.Numerics.BigInteger[]>> ImpossibleRsaKeys => new()
    {
        { "even public exponent", key => With(key, E, key[E] + 1) },
        { "public exponent 0", key => With(key, E, 0) },
        { "public exponent 1", key => With(key, E, 1) },
        { "private exponent 0", key => With(key, D, 0) },
        { "private exponent of another key", key => With(key, D, key[D] + 2) },
        { "even modulus", key => With(key, N, key[N] + 1) },
        { "modulus 0", key => With(key, N, 0) },
        { "modulus of another key", key => With(key, N, key[N] + 2) },
        { "prime 0", key => With(key, P, 0) },
        { "prime 1", key => With(key, P, 1) },
        { "prime 2", key => With(key, P, 2) },
        { "negative prime", key => With(key, P, -key[P]) },
        { "second prime 1", key => With(key, Q, 1) },
        { "a prime of another key", key => With(key, Q, key[Q] + 2) },
        { "the same prime twice", key => With(key, Q, key[P]) },
        // Consistent keys Go's ssh package still refuses (x/crypto ssh/keys.go): with a public
        // exponent of 1, RSA leaves the padded file key as it is, readable without the key.
        { "public exponent 1, private exponent 1", key => [key[N], 1, 1, key[Iqmp], key[P], key[Q]] },
        { "public exponent over 24 bits", key => WithPublicExponentOver24Bits(key) },
        { "nothing at all", key => [0, 0, 0, 0, 0, 0] },
    };

    /// <summary>
    /// An RSA key file states its numbers one by one, and BouncyCastle reads whatever is there:
    /// it fails on some of these with errors of its own (an even exponent, a division by zero)
    /// and accepts others, to fail only when it decrypts. OpenSSH and Go refuse them all.
    /// </summary>
    [Theory]
    [MemberData(nameof(ImpossibleRsaKeys))]
    public void ParseSshIdentity_RsaKeyThatCannotBeOne_ThrowsFormatException(string why, Func<System.Numerics.BigInteger[], System.Numerics.BigInteger[]> change)
    {
        _ = why;
        Assert.Throws<FormatException>(() => AgeKeygen.ParseSshIdentity(RsaKey(change)));
    }

    public static TheoryData<string, Func<System.Numerics.BigInteger[], System.Numerics.BigInteger[]>> RsaKeysWithStaleCrtValues => new()
    {
        { "a wrong CRT coefficient", key => With(key, Iqmp, key[Iqmp] + 1) },
        { "the primes in the other order", key => [key[N], key[E], key[D], key[Iqmp], key[Q], key[P]] },
    };

    /// <summary>
    /// The CRT coefficient is redundant: it follows from the primes. Go and OpenSSH compute their
    /// own and ignore the file's, so a key that states it wrongly still works for them — where
    /// BouncyCastle, trusting it, detects a faulty decryption and throws.
    /// </summary>
    [Theory]
    [MemberData(nameof(RsaKeysWithStaleCrtValues))]
    public void ParseSshIdentity_RsaKeyWithAStaleCrtValue_StillDecrypts(string why, Func<System.Numerics.BigInteger[], System.Numerics.BigInteger[]> change)
    {
        _ = why;
        var recipient = ((Age.Recipients.SshRsaIdentity)AgeKeygen.ParseSshIdentity(SshFixture("rsa_plain"))).Recipient;
        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream("plaintext"u8.ToArray()), encrypted, recipient);
        encrypted.Position = 0;
        using var decrypted = new MemoryStream();

        AgeEncrypt.Decrypt(encrypted, decrypted, AgeKeygen.ParseSshIdentity(RsaKey(change)));

        Assert.Equal("plaintext"u8.ToArray(), decrypted.ToArray());
    }

    // The smallest odd exponent of 25 bits that has an inverse, with its private exponent.
    private static System.Numerics.BigInteger[] WithPublicExponentOver24Bits(System.Numerics.BigInteger[] key)
    {
        var phi = (key[P] - 1) * (key[Q] - 1);
        var e = (System.Numerics.BigInteger.One << 24) + 1;
        while (System.Numerics.BigInteger.GreatestCommonDivisor(e, phi) != 1)
            e += 2;

        var d = new Org.BouncyCastle.Math.BigInteger(e.ToString()).ModInverse(new Org.BouncyCastle.Math.BigInteger(phi.ToString()));
        return [key[N], e, System.Numerics.BigInteger.Parse(d.ToString()), key[Iqmp], key[P], key[Q]];
    }

    // Go limits the public exponent to 24 bits for public keys and OpenSSH-format private keys
    // only; PKCS#1 and PKCS#8 keys go through its x509 package, which does not. openssl made
    // this one with an exponent of 2^25 + 1, and go-age decrypts with it.
    [Fact]
    public void ParseSshIdentity_Pkcs8RsaKeyWithAnExponentOver24Bits_Works()
    {
        var identity = (Age.Recipients.SshRsaIdentity)AgeKeygen.ParseSshIdentity(SshFixture("rsa_pkcs8_large_exponent"));
        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream("plaintext"u8.ToArray()), encrypted, identity.Recipient);
        encrypted.Position = 0;
        using var decrypted = new MemoryStream();

        AgeEncrypt.Decrypt(encrypted, decrypted, identity);

        Assert.Equal("plaintext"u8.ToArray(), decrypted.ToArray());
    }

    public static TheoryData<string, uint> ForbiddenRsaPublicExponents => new()
    {
        { "exponent 1", 1 },
        { "exponent even", 65538 },
        { "exponent over 24 bits", (1u << 24) + 1 },
    };

    /// <summary>
    /// The public exponents Go's ssh package refuses in a public key, refused in a recipient too.
    /// The line is built by hand: BouncyCastle would not encode some of these.
    /// </summary>
    [Theory]
    [MemberData(nameof(ForbiddenRsaPublicExponents))]
    public void ParseSshRecipient_RsaWithAForbiddenExponent_ThrowsFormatException(string why, uint exponent)
    {
        _ = why;
        var modulus = ((RsaKeyParameters)Rsa2048.Public).Modulus.ToByteArray();
        byte[] wire = [.. Field("ssh-rsa"u8.ToArray()), .. Field(Mpint(exponent)), .. Field(modulus)];

        var ex = Assert.Throws<FormatException>(() => AgeKeygen.ParseSshRecipient($"ssh-rsa {Convert.ToBase64String(wire)}"));

        Assert.Contains("exponent", ex.Message);
    }

    private static System.Numerics.BigInteger[] With(System.Numerics.BigInteger[] key, int field, System.Numerics.BigInteger value)
    {
        var changed = (System.Numerics.BigInteger[])key.Clone();
        changed[field] = value;
        return changed;
    }

    /// <summary>
    /// The unprotected rsa_plain fixture, written by ssh-keygen, with the numbers of its private
    /// key changed. The private section is: two check numbers, the key type, n, e, d, iqmp, p,
    /// q and the comment, then padding to 8 bytes.
    /// </summary>
    private static string RsaKey(Func<System.Numerics.BigInteger[], System.Numerics.BigInteger[]> change)
    {
        var pem = SshFixture("rsa_plain");
        var blob = Convert.FromBase64String(string.Concat(pem.Split('\n').Where(line => !line.StartsWith("-----"))));

        // The magic, then the cipher, the KDF, its options and the key count, then the public key.
        var offset = "openssh-key-v1\0".Length;
        for (var field = 0; field < 3; field++)
            ReadField(blob, ref offset);
        offset += 4;
        var beforeTheKeys = blob[..offset];
        var publicKey = ReadField(blob, ref offset);
        var section = ReadField(blob, ref offset);

        var position = 8;
        var keyType = ReadField(section, ref position);
        var numbers = new System.Numerics.BigInteger[6];
        for (var i = 0; i < numbers.Length; i++)
            numbers[i] = new System.Numerics.BigInteger(ReadField(section, ref position), isUnsigned: false, isBigEndian: true);
        var comment = ReadField(section, ref position);

        byte[] changed = [.. section[..8], .. Field(keyType), .. change(numbers).SelectMany(number => Field(Mpint(number))), .. Field(comment)];
        byte[] padding = [.. Enumerable.Range(1, (8 - changed.Length % 8) % 8).Select(i => (byte)i)];

        return Pem("OPENSSH PRIVATE KEY", [.. beforeTheKeys, .. Field(publicKey), .. Field([.. changed, .. padding])]);
    }

    private static string SshFixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private static byte[] ReadField(byte[] from, ref int offset)
    {
        var length = (int)BinaryPrimitives.ReadUInt32BigEndian(from.AsSpan(offset));
        var field = from.AsSpan(offset + 4, length).ToArray();
        offset += 4 + length;
        return field;
    }

    private static byte[] Field(byte[] value)
    {
        var field = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt32BigEndian(field, (uint)value.Length);
        value.CopyTo(field, 4);
        return field;
    }

    // An SSH mpint: big-endian two's complement in as few bytes as it takes, and none for zero.
    private static byte[] Mpint(System.Numerics.BigInteger value) =>
        value.IsZero ? [] : value.ToByteArray(isUnsigned: false, isBigEndian: true);

    private static AsymmetricCipherKeyPair GenerateRsa(int bits)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), bits));
        return generator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair EcdsaP256()
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(
            Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    private static string Wire(AsymmetricCipherKeyPair pair) =>
        Convert.ToBase64String(OpenSshPublicKeyUtilities.EncodePublicKey(pair.Public));

    private static string EncryptedPem(Org.BouncyCastle.Utilities.IO.Pem.PemObjectGenerator generator)
    {
        using var text = new StringWriter();
        new PemWriter(text).WriteObject(generator);
        return text.ToString();
    }

    /// <summary>
    /// The openssh-key-v1 layout ssh-keygen -N writes: the cipher and KDF are named up front, so
    /// the key reads as passphrase-protected before its encrypted section is ever looked at.
    /// </summary>
    private static string PassphraseProtectedOpenSsh()
    {
        using var blob = new MemoryStream();
        blob.Write("openssh-key-v1\0"u8);
        WriteString(blob, "aes256-ctr"u8);
        WriteString(blob, "bcrypt"u8);
        WriteString(blob, RandomNumberGenerator.GetBytes(24));
        WriteUInt32(blob, 1);
        WriteString(blob, Ed25519Wire);
        WriteString(blob, RandomNumberGenerator.GetBytes(160));
        return Pem("OPENSSH PRIVATE KEY", blob.ToArray());

        static void WriteString(Stream s, ReadOnlySpan<byte> value)
        {
            WriteUInt32(s, (uint)value.Length);
            s.Write(value);
        }

        static void WriteUInt32(Stream s, uint value)
        {
            Span<byte> be = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(be, value);
            s.Write(be);
        }
    }

    private static string Pem(string label, byte[] body)
    {
        var sb = new StringBuilder().Append($"-----BEGIN {label}-----\n");
        var b64 = Convert.ToBase64String(body);
        for (var i = 0; i < b64.Length; i += 70)
            sb.Append(b64.AsSpan(i, Math.Min(70, b64.Length - i))).Append('\n');
        return sb.Append($"-----END {label}-----\n").ToString();
    }
}
