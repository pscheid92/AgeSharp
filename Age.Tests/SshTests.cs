using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Age;
using Age.Crypto;
using Age.Recipients;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Xunit;

namespace Age.Tests;

public class Ed25519ConverterTests
{
    [Fact]
    public void PublicKeyToX25519_KnownVector()
    {
        // Generate an Ed25519 key pair and verify the conversion matches
        // what BouncyCastle's X25519 would produce from the same seed
        var seed = new byte[32];
        new Random(42).NextBytes(seed);

        var ed25519Priv = new Ed25519PrivateKeyParameters(seed);
        var ed25519Pub = ed25519Priv.GeneratePublicKey().GetEncoded();

        // Convert via our converter
        var x25519Pub = Ed25519Converter.PublicKeyToX25519(ed25519Pub);
        Assert.Equal(32, x25519Pub.Length);

        // Convert private key and derive public key independently
        var x25519Priv = Ed25519Converter.PrivateKeyToX25519(seed);
        var x25519PrivParam = new X25519PrivateKeyParameters(x25519Priv);
        var x25519PubFromPriv = x25519PrivParam.GeneratePublicKey().GetEncoded();

        // Both methods should produce the same X25519 public key
        Assert.Equal(x25519PubFromPriv, x25519Pub);
    }

    [Fact]
    public void PrivateKeyToX25519_IsSha512FirstHalf()
    {
        var seed = new byte[32];
        new Random(99).NextBytes(seed);

        var x25519Priv = Ed25519Converter.PrivateKeyToX25519(seed);
        Assert.Equal(32, x25519Priv.Length);

        // Verify it's SHA-512(seed)[0..32]
        var sha512 = SHA512.HashData(seed);
        Assert.Equal(sha512[..32], x25519Priv);
    }

    [Fact]
    public void PublicKeyToX25519_RejectsWrongLength()
    {
        Assert.Throws<ArgumentException>(() => Ed25519Converter.PublicKeyToX25519(new byte[16]));
    }

    [Fact]
    public void PrivateKeyToX25519_RejectsWrongLength()
    {
        Assert.Throws<ArgumentException>(() => Ed25519Converter.PrivateKeyToX25519(new byte[16]));
    }

    [Fact]
    public void PublicKeyToX25519_MultipleKeys_Distinct()
    {
        var results = new List<byte[]>();
        for (int i = 0; i < 5; i++)
        {
            var seed = new byte[32];
            new Random(i).NextBytes(seed);
            var ed25519Priv = new Ed25519PrivateKeyParameters(seed);
            var ed25519Pub = ed25519Priv.GeneratePublicKey().GetEncoded();
            results.Add(Ed25519Converter.PublicKeyToX25519(ed25519Pub));
        }

        // All results should be distinct
        for (int i = 0; i < results.Count; i++)
            for (int j = i + 1; j < results.Count; j++)
                Assert.NotEqual(results[i], results[j]);
    }
}

public class SshKeyParserTests
{
    [Fact]
    public void ParsePublicKey_Ed25519()
    {
        // Generate an Ed25519 key and format as authorized_keys
        var seed = new byte[32];
        new Random(42).NextBytes(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var pub = priv.GeneratePublicKey();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(pub);
        var authorizedKeysLine = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test@example.com";

        var (keyType, parsedWire, parsedKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        Assert.Equal("ssh-ed25519", keyType);
        Assert.Equal(wireBytes, parsedWire);
        Assert.IsType<Ed25519PublicKeyParameters>(parsedKey);
    }

    [Fact]
    public void ParsePublicKey_Rsa()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(kp.Public);
        var authorizedKeysLine = $"ssh-rsa {Convert.ToBase64String(wireBytes)} test@example.com";

        var (keyType, parsedWire, parsedKey) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        Assert.Equal("ssh-rsa", keyType);
        Assert.Equal(wireBytes, parsedWire);
        Assert.IsType<RsaKeyParameters>(parsedKey);
    }

    [Fact]
    public void ParsePublicKey_RejectsUnsupportedType()
    {
        Assert.Throws<FormatException>(() =>
            SshKeyParser.ParsePublicKey("ssh-dss AAAA test@example.com"));
    }

    [Fact]
    public void ParsePublicKey_RejectsTooFewFields()
    {
        Assert.Throws<FormatException>(() =>
            SshKeyParser.ParsePublicKey("ssh-ed25519"));
    }

    [Fact]
    public void ComputeTag_Deterministic()
    {
        var wireBytes = new byte[51]; // typical Ed25519 wire bytes length
        new Random(42).NextBytes(wireBytes);

        var tag1 = SshKeyParser.ComputeTag(wireBytes);
        var tag2 = SshKeyParser.ComputeTag(wireBytes);

        Assert.Equal(tag1, tag2);
        // Tag is base64_unpadded(SHA-256(wireBytes)[:4]) = ceil(4*4/3)=6 chars without padding
        Assert.True(tag1.Length <= 8);
    }

    [Fact]
    public void ComputeTag_DifferentKeys_DifferentTags()
    {
        var wire1 = new byte[51];
        var wire2 = new byte[51];
        new Random(1).NextBytes(wire1);
        new Random(2).NextBytes(wire2);

        Assert.NotEqual(SshKeyParser.ComputeTag(wire1), SshKeyParser.ComputeTag(wire2));
    }

    [Fact]
    public void ParsePublicKey_RejectsInvalidBase64()
    {
        var ex = Assert.Throws<FormatException>(() =>
            SshKeyParser.ParsePublicKey("ssh-ed25519 @@@not-base64@@@ test"));
        Assert.Contains("invalid base64", ex.Message);
    }

    [Fact]
    public void ParsePrivateKey_Pkcs1Rsa()
    {
        // Generate RSA key pair and encode as PKCS#1 PEM
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();

        var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(kp.Private);
        var pkcs1Pem = sw.ToString();

        Assert.Contains("BEGIN RSA PRIVATE KEY", pkcs1Pem);

        var (keyType, wireBytes, privKey) = SshKeyParser.ParsePrivateKey(pkcs1Pem);
        Assert.Equal("ssh-rsa", keyType);
        Assert.IsType<RsaPrivateCrtKeyParameters>(privKey);
        Assert.True(wireBytes.Length > 0);
    }

    [Fact]
    public void ParsePrivateKey_Pkcs8Rsa()
    {
        // Generate RSA key pair and encode as PKCS#8 PEM
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();

        var pkcs8Info = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
        var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(sw);
        pemWriter.WriteObject(new Org.BouncyCastle.Utilities.IO.Pem.PemObject("PRIVATE KEY", pkcs8Info.GetEncoded()));
        var pkcs8Pem = sw.ToString();

        Assert.Contains("BEGIN PRIVATE KEY", pkcs8Pem);

        var (keyType, wireBytes, privKey) = SshKeyParser.ParsePrivateKey(pkcs8Pem);
        Assert.Equal("ssh-rsa", keyType);
        Assert.IsType<RsaPrivateCrtKeyParameters>(privKey);
    }

    [Fact]
    public void ParsePrivateKey_RejectsPublicKeyPem()
    {
        // A PEM containing a public key (not a private key) should be rejected
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();

        var pubInfo = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public);
        var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(sw);
        pemWriter.WriteObject(new Org.BouncyCastle.Utilities.IO.Pem.PemObject("PUBLIC KEY", pubInfo.GetEncoded()));
        var pubPem = sw.ToString();

        Assert.Throws<FormatException>(() => SshKeyParser.ParsePrivateKey(pubPem));
    }

    [Fact]
    public void ParsePrivateKey_Pkcs1Rsa_RoundTripsWithRecipient()
    {
        // Full round-trip: PKCS#1 PEM → identity → wrap/unwrap
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();

        var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(kp.Private);
        var pkcs1Pem = sw.ToString();

        using var identity = SshRsaIdentity.Parse(pkcs1Pem);
        var recipient = identity.Recipient;

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        Assert.NotNull(unwrapped);
        Assert.Equal(fileKey, unwrapped);
    }
}

public class SshEd25519RecipientIdentityTests
{
    private static (string authorizedKeys, string pemText) GenerateEd25519KeyPair()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var pub = priv.GeneratePublicKey();

        // Build authorized_keys line
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(pub);
        var authorizedKeys = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test@example.com";

        // Build OpenSSH PEM
        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(priv);
        var pemText = BuildOpenSshPem(privBlob);

        return (authorizedKeys, pemText);
    }

    private static string BuildOpenSshPem(byte[] blob)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----");
        var b64 = Convert.ToBase64String(blob);
        for (int i = 0; i < b64.Length; i += 70)
        {
            sb.AppendLine(b64.Substring(i, Math.Min(70, b64.Length - i)));
        }
        sb.AppendLine("-----END OPENSSH PRIVATE KEY-----");
        return sb.ToString();
    }

    [Fact]
    public void WrapUnwrap_RoundTrip()
    {
        var (authorizedKeys, pemText) = GenerateEd25519KeyPair();
        var recipient = SshEd25519Recipient.Parse(authorizedKeys);
        using var identity = SshEd25519Identity.Parse(pemText);

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        Assert.NotNull(unwrapped);
        Assert.Equal(fileKey, unwrapped);
    }

    [Fact]
    public void Unwrap_WrongIdentity_ReturnsNull()
    {
        var (authorizedKeys1, _) = GenerateEd25519KeyPair();
        var (_, pemText2) = GenerateEd25519KeyPair();

        var recipient = SshEd25519Recipient.Parse(authorizedKeys1);
        using var identity = SshEd25519Identity.Parse(pemText2);

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        // Tag mismatch → null
        Assert.Null(unwrapped);
    }

    [Fact]
    public void Unwrap_WrongStanzaType_ReturnsNull()
    {
        var (_, pemText) = GenerateEd25519KeyPair();
        using var identity = SshEd25519Identity.Parse(pemText);

        var stanza = new Age.Format.Stanza("X25519", ["arg"], new byte[32]);
        Assert.Null(identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_WrongArgCount_Throws()
    {
        var (_, pemText) = GenerateEd25519KeyPair();
        using var identity = SshEd25519Identity.Parse(pemText);

        var stanza = new Age.Format.Stanza("ssh-ed25519", ["onlyone"], new byte[32]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Stanza_HasCorrectType()
    {
        var (authorizedKeys, _) = GenerateEd25519KeyPair();
        var recipient = SshEd25519Recipient.Parse(authorizedKeys);

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var stanza = recipient.Wrap(fileKey);

        Assert.Equal("ssh-ed25519", stanza.Type);
        Assert.Equal(2, stanza.Args.Length);
        Assert.Equal(32, stanza.Body.Length); // 16 bytes plaintext + 16 bytes tag
    }

    [Fact]
    public void Recipient_FromIdentity_RoundTrips()
    {
        var (_, pemText) = GenerateEd25519KeyPair();
        using var identity = SshEd25519Identity.Parse(pemText);
        var recipient = identity.Recipient;

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        Assert.NotNull(unwrapped);
        Assert.Equal(fileKey, unwrapped);
    }

    [Fact]
    public void Label_IsNull()
    {
        var (authorizedKeys, _) = GenerateEd25519KeyPair();
        var recipient = SshEd25519Recipient.Parse(authorizedKeys);
        Assert.Null(((IRecipient)recipient).Label);
    }

    [Fact]
    public void Parse_RejectsRsaKey()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(kp.Public);
        var authorizedKeys = $"ssh-rsa {Convert.ToBase64String(wireBytes)} test@example.com";

        Assert.Throws<FormatException>(() => SshEd25519Recipient.Parse(authorizedKeys));
    }

    [Fact]
    public void IdentityParse_RejectsRsaPem()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();
        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(kp.Private);
        var pemText = BuildOpenSshPem(privBlob);

        Assert.Throws<FormatException>(() => SshEd25519Identity.Parse(pemText));
    }

    [Fact]
    public void Unwrap_InvalidEphKeyEncoding_Throws()
    {
        var (_, pemText) = GenerateEd25519KeyPair();
        using var identity = SshEd25519Identity.Parse(pemText);

        // Build stanza with matching tag but invalid base64 for ephemeral key
        var recipient = identity.Recipient;
        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var goodStanza = recipient.Wrap(fileKey);

        // Replace the ephemeral key arg with invalid base64
        var stanza = new Age.Format.Stanza("ssh-ed25519", [goodStanza.Args[0], "@@invalid@@"], goodStanza.Body);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_WrongEphKeyLength_Throws()
    {
        var (_, pemText) = GenerateEd25519KeyPair();
        using var identity = SshEd25519Identity.Parse(pemText);

        var recipient = identity.Recipient;
        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var goodStanza = recipient.Wrap(fileKey);

        // Replace ephemeral key with wrong length (16 bytes instead of 32)
        var shortKeyB64 = Age.Crypto.Base64Unpadded.Encode(new byte[16]);
        var stanza = new Age.Format.Stanza("ssh-ed25519", [goodStanza.Args[0], shortKeyB64], goodStanza.Body);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_WrongBodyLength_Throws()
    {
        var (_, pemText) = GenerateEd25519KeyPair();
        using var identity = SshEd25519Identity.Parse(pemText);

        var recipient = identity.Recipient;
        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var goodStanza = recipient.Wrap(fileKey);

        // Replace body with wrong length
        var stanza = new Age.Format.Stanza("ssh-ed25519", goodStanza.Args, new byte[16]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }
}

public class SshRsaRecipientIdentityTests
{
    private static (string authorizedKeys, string pemText) GenerateRsaKeyPair()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();

        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(kp.Public);
        var authorizedKeys = $"ssh-rsa {Convert.ToBase64String(wireBytes)} test@example.com";

        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(kp.Private);
        var pemText = BuildOpenSshPem(privBlob);

        return (authorizedKeys, pemText);
    }

    private static string BuildOpenSshPem(byte[] blob)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----");
        var b64 = Convert.ToBase64String(blob);
        for (int i = 0; i < b64.Length; i += 70)
        {
            sb.AppendLine(b64.Substring(i, Math.Min(70, b64.Length - i)));
        }
        sb.AppendLine("-----END OPENSSH PRIVATE KEY-----");
        return sb.ToString();
    }

    [Fact]
    public void WrapUnwrap_RoundTrip()
    {
        var (authorizedKeys, pemText) = GenerateRsaKeyPair();
        var recipient = SshRsaRecipient.Parse(authorizedKeys);
        using var identity = SshRsaIdentity.Parse(pemText);

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        Assert.NotNull(unwrapped);
        Assert.Equal(fileKey, unwrapped);
    }

    [Fact]
    public void Unwrap_WrongKey_ReturnsNull()
    {
        var (authorizedKeys1, _) = GenerateRsaKeyPair();
        var (_, pemText2) = GenerateRsaKeyPair();

        var recipient = SshRsaRecipient.Parse(authorizedKeys1);
        using var identity = SshRsaIdentity.Parse(pemText2);

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        // Tag mismatch → null
        Assert.Null(unwrapped);
    }

    [Fact]
    public void Unwrap_WrongStanzaType_ReturnsNull()
    {
        var (_, pemText) = GenerateRsaKeyPair();
        using var identity = SshRsaIdentity.Parse(pemText);

        var stanza = new Age.Format.Stanza("X25519", ["arg"], new byte[32]);
        Assert.Null(identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_WrongArgCount_Throws()
    {
        var (_, pemText) = GenerateRsaKeyPair();
        using var identity = SshRsaIdentity.Parse(pemText);

        var stanza = new Age.Format.Stanza("ssh-rsa", ["tag", "extra"], new byte[256]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Stanza_HasCorrectType()
    {
        var (authorizedKeys, _) = GenerateRsaKeyPair();
        var recipient = SshRsaRecipient.Parse(authorizedKeys);

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var stanza = recipient.Wrap(fileKey);

        Assert.Equal("ssh-rsa", stanza.Type);
        Assert.Single(stanza.Args);
        Assert.Equal(256, stanza.Body.Length); // 2048-bit RSA = 256 bytes
    }

    [Fact]
    public void Recipient_FromIdentity_RoundTrips()
    {
        var (_, pemText) = GenerateRsaKeyPair();
        using var identity = SshRsaIdentity.Parse(pemText);
        var recipient = identity.Recipient;

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        var stanza = recipient.Wrap(fileKey);
        var unwrapped = identity.Unwrap(stanza);

        Assert.NotNull(unwrapped);
        Assert.Equal(fileKey, unwrapped);
    }

    [Fact]
    public void RejectsSmallKey()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 1024));
        var kp = rsaGen.GenerateKeyPair();

        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(kp.Public);

        Assert.Throws<ArgumentException>(() =>
            new SshRsaRecipient((RsaKeyParameters)kp.Public, wireBytes));
    }

    [Fact]
    public void Label_IsNull()
    {
        var (authorizedKeys, _) = GenerateRsaKeyPair();
        var recipient = SshRsaRecipient.Parse(authorizedKeys);
        Assert.Null(((IRecipient)recipient).Label);
    }

    [Fact]
    public void Parse_RejectsEd25519Key()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var pub = priv.GeneratePublicKey();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(pub);
        var authorizedKeys = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test@example.com";

        Assert.Throws<FormatException>(() => SshRsaRecipient.Parse(authorizedKeys));
    }

    [Fact]
    public void IdentityParse_RejectsEd25519Pem()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(priv);
        var pemText = BuildOpenSshPem(privBlob);

        Assert.Throws<FormatException>(() => SshRsaIdentity.Parse(pemText));
    }

    [Fact]
    public void Unwrap_CorruptBody_ReturnsNull()
    {
        // Encrypt to RSA, then corrupt the OAEP ciphertext body
        var (_, pemText) = GenerateRsaKeyPair();
        using var identity = SshRsaIdentity.Parse(pemText);
        var recipient = identity.Recipient;

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var stanza = recipient.Wrap(fileKey);

        // Create a body that's valid RSA size but with zeroed content — will fail OAEP decoding
        var corruptBody = new byte[stanza.Body.Length];
        // Fill with a value that's less than the modulus but will fail OAEP padding check
        corruptBody[1] = 0x02; // Ensure it's < modulus
        var corruptStanza = new Age.Format.Stanza("ssh-rsa", stanza.Args, corruptBody);

        Assert.Null(identity.Unwrap(corruptStanza));
    }

    [Fact]
    public void Unwrap_OversizedBody_ReturnsNull()
    {
        // Body larger than RSA modulus triggers DataLengthException
        var (_, pemText) = GenerateRsaKeyPair();
        using var identity = SshRsaIdentity.Parse(pemText);
        var recipient = identity.Recipient;

        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);
        var stanza = recipient.Wrap(fileKey);

        // Body larger than 256 bytes (2048-bit key) triggers "input too large for RSA cipher"
        var oversizedBody = new byte[512];
        RandomNumberGenerator.Fill(oversizedBody);
        var oversizedStanza = new Age.Format.Stanza("ssh-rsa", stanza.Args, oversizedBody);

        Assert.Null(identity.Unwrap(oversizedStanza));
    }
}

public class SshRoundTripTests
{
    private static string BuildOpenSshPem(byte[] blob)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----");
        var b64 = Convert.ToBase64String(blob);
        for (int i = 0; i < b64.Length; i += 70)
        {
            sb.AppendLine(b64.Substring(i, Math.Min(70, b64.Length - i)));
        }
        sb.AppendLine("-----END OPENSSH PRIVATE KEY-----");
        return sb.ToString();
    }

    [Fact]
    public void SshEd25519_FullEncryptDecrypt()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var pub = priv.GeneratePublicKey();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(pub);
        var authorizedKeys = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test";

        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(priv);
        var pemText = BuildOpenSshPem(privBlob);

        var recipient = SshEd25519Recipient.Parse(authorizedKeys);
        using var identity = SshEd25519Identity.Parse(pemText);

        var plaintext = "Hello, SSH Ed25519!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void SshRsa_FullEncryptDecrypt()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();

        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(kp.Public);
        var authorizedKeys = $"ssh-rsa {Convert.ToBase64String(wireBytes)} test";

        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(kp.Private);
        var pemText = BuildOpenSshPem(privBlob);

        var recipient = SshRsaRecipient.Parse(authorizedKeys);
        using var identity = SshRsaIdentity.Parse(pemText);

        var plaintext = "Hello, SSH RSA!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void SshMixed_X25519AndSshRecipients()
    {
        // Encrypt to both X25519 and SSH Ed25519 recipients
        using var x25519Identity = X25519Identity.Generate();

        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var ed25519Priv = new Ed25519PrivateKeyParameters(seed);
        var ed25519Pub = ed25519Priv.GeneratePublicKey();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(ed25519Pub);
        var authorizedKeys = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test";
        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(ed25519Priv);
        var pemText = BuildOpenSshPem(privBlob);

        var sshRecipient = SshEd25519Recipient.Parse(authorizedKeys);
        using var sshIdentity = SshEd25519Identity.Parse(pemText);

        var plaintext = "Multi-recipient test"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, x25519Identity.Recipient, sshRecipient);

        // Decrypt with X25519 identity
        encOutput.Position = 0;
        using var decOutput1 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput1, x25519Identity);
        Assert.Equal(plaintext, decOutput1.ToArray());

        // Decrypt with SSH identity
        encOutput.Position = 0;
        using var decOutput2 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput2, sshIdentity);
        Assert.Equal(plaintext, decOutput2.ToArray());
    }

    [Fact]
    public void AgeKeygen_ParseSshRecipient_Ed25519()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var pub = priv.GeneratePublicKey();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(pub);
        var line = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test";

        var recipient = AgeKeygen.ParseSshRecipient(line);
        Assert.IsType<SshEd25519Recipient>(recipient);
    }

    [Fact]
    public void AgeKeygen_ParseSshRecipient_Rsa()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();
        var wireBytes = OpenSshPublicKeyUtilities.EncodePublicKey(kp.Public);
        var line = $"ssh-rsa {Convert.ToBase64String(wireBytes)} test";

        var recipient = AgeKeygen.ParseSshRecipient(line);
        Assert.IsType<SshRsaRecipient>(recipient);
    }

    [Fact]
    public void AgeKeygen_ParseSshIdentity_Ed25519()
    {
        var seed = new byte[32];
        RandomNumberGenerator.Fill(seed);
        var priv = new Ed25519PrivateKeyParameters(seed);
        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(priv);
        var pemText = BuildOpenSshPem(privBlob);

        var identity = AgeKeygen.ParseSshIdentity(pemText);
        Assert.IsType<SshEd25519Identity>(identity);
    }

    [Fact]
    public void AgeKeygen_ParseSshIdentity_Rsa()
    {
        var rsaGen = new RsaKeyPairGenerator();
        rsaGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = rsaGen.GenerateKeyPair();
        var privBlob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(kp.Private);
        var pemText = BuildOpenSshPem(privBlob);

        var identity = AgeKeygen.ParseSshIdentity(pemText);
        Assert.IsType<SshRsaIdentity>(identity);
    }

    [Fact]
    public void Interop_SshEd25519_EncryptWithCSharp_DecryptWithAgeCli()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return;

        // Generate key pair using ssh-keygen
        var tmpDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var keyPath = Path.Combine(tmpDir, "id_ed25519");

        try
        {
            // Generate SSH Ed25519 key pair
            var keygenPsi = new ProcessStartInfo("ssh-keygen", $"-t ed25519 -f {keyPath} -N \"\" -q")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var keygenProc = Process.Start(keygenPsi)!;
            keygenProc.WaitForExit();
            if (keygenProc.ExitCode != 0) return; // skip if ssh-keygen not available

            var pubKeyLine = File.ReadAllText(keyPath + ".pub").Trim();
            var privKeyPem = File.ReadAllText(keyPath);

            // Encrypt with C#
            var recipient = SshEd25519Recipient.Parse(pubKeyLine);
            var plaintext = "Hello from C# SSH Ed25519!"u8.ToArray();

            using var encInput = new MemoryStream(plaintext);
            using var encOutput = new MemoryStream();
            AgeEncrypt.Encrypt(encInput, encOutput, recipient);

            var cipherPath = Path.Combine(tmpDir, "encrypted.age");
            File.WriteAllBytes(cipherPath, encOutput.ToArray());

            // Decrypt with age CLI using SSH key
            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-d -i {keyPath} {cipherPath}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            Assert.Equal(0, proc.ExitCode);
            Assert.Equal("Hello from C# SSH Ed25519!", output);
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }

    [Fact]
    public void Interop_SshEd25519_EncryptWithAgeCli_DecryptWithCSharp()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return;

        var tmpDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var keyPath = Path.Combine(tmpDir, "id_ed25519");

        try
        {
            // Generate SSH Ed25519 key pair
            var keygenPsi = new ProcessStartInfo("ssh-keygen", $"-t ed25519 -f {keyPath} -N \"\" -q")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var keygenProc = Process.Start(keygenPsi)!;
            keygenProc.WaitForExit();
            if (keygenProc.ExitCode != 0) return;

            var pubKeyLine = File.ReadAllText(keyPath + ".pub").Trim();
            var privKeyPem = File.ReadAllText(keyPath);

            // Encrypt with age CLI using SSH public key
            var cipherPath = Path.Combine(tmpDir, "encrypted.age");
            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-R {keyPath}.pub -o {cipherPath}")
            {
                RedirectStandardInput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            proc.StandardInput.Write("Hello from age CLI SSH!");
            proc.StandardInput.Close();
            proc.WaitForExit();
            if (proc.ExitCode != 0) return;

            // Decrypt with C#
            using var identity = SshEd25519Identity.Parse(privKeyPem);
            var ciphertext = File.ReadAllBytes(cipherPath);
            using var decInput = new MemoryStream(ciphertext);
            using var decOutput = new MemoryStream();
            AgeEncrypt.Decrypt(decInput, decOutput, identity);

            var result = Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("Hello from age CLI SSH!", result);
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }

    [Fact]
    public void Interop_SshRsa_EncryptWithCSharp_DecryptWithAgeCli()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return;

        var tmpDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var keyPath = Path.Combine(tmpDir, "id_rsa");

        try
        {
            var keygenPsi = new ProcessStartInfo("ssh-keygen", $"-t rsa -b 2048 -f {keyPath} -N \"\" -q")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var keygenProc = Process.Start(keygenPsi)!;
            keygenProc.WaitForExit();
            if (keygenProc.ExitCode != 0) return;

            var pubKeyLine = File.ReadAllText(keyPath + ".pub").Trim();

            // Encrypt with C#
            var recipient = SshRsaRecipient.Parse(pubKeyLine);
            var plaintext = "Hello from C# SSH RSA!"u8.ToArray();

            using var encInput = new MemoryStream(plaintext);
            using var encOutput = new MemoryStream();
            AgeEncrypt.Encrypt(encInput, encOutput, recipient);

            var cipherPath = Path.Combine(tmpDir, "encrypted.age");
            File.WriteAllBytes(cipherPath, encOutput.ToArray());

            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-d -i {keyPath} {cipherPath}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            Assert.Equal(0, proc.ExitCode);
            Assert.Equal("Hello from C# SSH RSA!", output);
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }

    [Fact]
    public void Interop_SshRsa_EncryptWithAgeCli_DecryptWithCSharp()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return;

        var tmpDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);
        var keyPath = Path.Combine(tmpDir, "id_rsa");

        try
        {
            var keygenPsi = new ProcessStartInfo("ssh-keygen", $"-t rsa -b 2048 -f {keyPath} -N \"\" -q")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var keygenProc = Process.Start(keygenPsi)!;
            keygenProc.WaitForExit();
            if (keygenProc.ExitCode != 0) return;

            var pubKeyLine = File.ReadAllText(keyPath + ".pub").Trim();
            var privKeyPem = File.ReadAllText(keyPath);

            var cipherPath = Path.Combine(tmpDir, "encrypted.age");
            var psi = new ProcessStartInfo("/opt/homebrew/bin/age", $"-R {keyPath}.pub -o {cipherPath}")
            {
                RedirectStandardInput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi)!;
            proc.StandardInput.Write("Hello from age CLI RSA!");
            proc.StandardInput.Close();
            proc.WaitForExit();
            if (proc.ExitCode != 0) return;

            using var identity = SshRsaIdentity.Parse(privKeyPem);
            var ciphertext = File.ReadAllBytes(cipherPath);
            using var decInput = new MemoryStream(ciphertext);
            using var decOutput = new MemoryStream();
            AgeEncrypt.Decrypt(decInput, decOutput, identity);

            var result = Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("Hello from age CLI RSA!", result);
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }
}
