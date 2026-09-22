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
/// authorized_keys type field, and the CLI reports anything else as "This is a bug".
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
        { "pkcs#8 pem", EncryptedPem(new Pkcs8Generator(Rsa1024.Private, Pkcs8Generator.PbeSha1_3DES) { Password = "pw".ToCharArray() }) },
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
