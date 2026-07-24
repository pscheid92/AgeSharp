using System.Text;
using AgeSharp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// The TryParse contract: true + a usable value for valid input, false — never
/// an exception — for null or malformed input; and the bech32 four are usable
/// through generic <see cref="IParsable{TSelf}"/> code.
/// </summary>
public class TryParseTests
{
    // --- bech32 four: valid input round-trips ---

    [Fact]
    public void X25519Identity_TryParse_Valid_RoundTrips()
    {
        using var identity = X25519Identity.Generate();

        Assert.True(X25519Identity.TryParse(identity.ToSecretString(), out var parsed));
        Assert.Equal(identity.ToSecretString(), parsed.ToSecretString());
        parsed.Dispose();
    }

    [Fact]
    public void X25519Recipient_TryParse_Valid_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        Assert.True(X25519Recipient.TryParse(recipientStr, out var parsed));
        Assert.Equal(recipientStr, parsed.ToString());
    }

    [Fact]
    public void MlKem768X25519Identity_TryParse_Valid_RoundTrips()
    {
        using var identity = MlKem768X25519Identity.Generate();

        Assert.True(MlKem768X25519Identity.TryParse(identity.ToSecretString(), out var parsed));
        Assert.Equal(identity.ToSecretString(), parsed.ToSecretString());
        parsed.Dispose();
    }

    [Fact]
    public void MlKem768X25519Recipient_TryParse_Valid_RoundTrips()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        Assert.True(MlKem768X25519Recipient.TryParse(recipientStr, out var parsed));
        Assert.Equal(recipientStr, parsed.ToString());
    }

    // --- bech32 four: every malformed case the Parse tests cover returns false ---

    // Fixed vectors: malformed inputs must be deterministic — a mutation of a
    // randomly generated key can collide with the original (e.g. replacing the
    // last char with one it already has), turning the test flaky.
    private const string ValidSecret = "AGE-SECRET-KEY-18RJY3RWGJ434MU5AP9NVSWYCHFT7NRA75L5X4LAYJ4V0Q8QXQD7QZTMR59";
    private const string ValidRecipient = "age1j0lauh038m0thy3lq0yvhnzehhy08s45nxwzk2f9hukgzucsw3ps60kslt";
    private const string ValidPqSecret = "AGE-SECRET-KEY-PQ-10CMEPS4C0AVQEQTEMKTK6HSPZWVXQL4RVSHYTE9HHA63G2DMEV7SXPGM0S";

    public static TheoryData<string?> MalformedX25519IdentityInputs() =>
    [
        null,
        "",
        "not bech32 at all",
        ValidSecret.ToLowerInvariant(),   // must be uppercase
        ValidRecipient,                   // wrong HRP (recipient)
        ValidPqSecret,                    // wrong HRP (PQ secret)
        ValidSecret[..^1] + "X",          // checksum broken (last char is '9')
    ];

    [Theory]
    [MemberData(nameof(MalformedX25519IdentityInputs))]
    public void X25519Identity_TryParse_Malformed_ReturnsFalse(string? input)
    {
        Assert.False(X25519Identity.TryParse(input, out var result));
        Assert.Null(result);
    }

    public static TheoryData<string?> MalformedX25519RecipientInputs() =>
    [
        null,
        "",
        "age1",                              // no data
        ValidRecipient.ToUpperInvariant(),   // must be lowercase
        ValidSecret,                         // wrong HRP (secret key)
        ValidRecipient[..^1] + "x",          // checksum broken (last char is 't')
    ];

    [Theory]
    [MemberData(nameof(MalformedX25519RecipientInputs))]
    public void X25519Recipient_TryParse_Malformed_ReturnsFalse(string? input)
    {
        Assert.False(X25519Recipient.TryParse(input, out var result));
        Assert.Null(result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("AGE-SECRET-KEY-1QQQQQQQQ")]  // X25519 HRP, not PQ
    public void MlKem768X25519Identity_TryParse_Malformed_ReturnsFalse(string? input)
    {
        Assert.False(MlKem768X25519Identity.TryParse(input, out var result));
        Assert.Null(result);
    }

    [Fact]
    public void MlKem768X25519Recipient_TryParse_X25519Recipient_ReturnsFalse()
    {
        using var identity = X25519Identity.Generate();
        Assert.False(MlKem768X25519Recipient.TryParse(identity.Recipient.ToString(), out var result));
        Assert.Null(result);
    }

    // --- generic IParsable usage ---

    private static T ParseVia<T>(string s) where T : IParsable<T> => T.Parse(s, null);

    private static bool TryParseVia<T>(string? s, out T? result) where T : IParsable<T>
        => T.TryParse(s, null, out result);

    [Fact]
    public void IParsable_Works_In_Generic_Context()
    {
        using var identity = X25519Identity.Generate();

        using var parsed = ParseVia<X25519Identity>(identity.ToSecretString());
        Assert.Equal(identity.ToSecretString(), parsed.ToSecretString());

        Assert.True(TryParseVia<X25519Recipient>(identity.Recipient.ToString(), out var recipient));
        Assert.Equal(identity.Recipient.ToString(), recipient!.ToString());

        Assert.False(TryParseVia<MlKem768X25519Identity>("garbage", out var none));
        Assert.Null(none);
    }

    [Fact]
    public void IParsable_Parse_Malformed_Throws_AgeFormatException()
    {
        Assert.Throws<AgeFormatException>(() => ParseVia<X25519Identity>("garbage"));
    }

    [Fact]
    public void IParsable_All_Four_Types_Work_Generically()
    {
        using var x = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();

        AssertParsable<X25519Identity>(x.ToSecretString());
        AssertParsable<X25519Recipient>(x.Recipient.ToString());
        AssertParsable<MlKem768X25519Identity>(pq.ToSecretString());
        AssertParsable<MlKem768X25519Recipient>(pq.Recipient.ToString());
    }

    private static void AssertParsable<T>(string valid) where T : IParsable<T>
    {
        var parsed = T.Parse(valid, null);
        Assert.NotNull(parsed);
        (parsed as IDisposable)?.Dispose();

        Assert.True(T.TryParse(valid, null, out var viaTry));
        (viaTry as IDisposable)?.Dispose();

        Assert.False(T.TryParse("garbage", null, out var none));
        Assert.Null(none);
    }

    // --- SSH types: valid input ---

    [Fact]
    public void SshEd25519_TryParse_Valid_Succeeds()
    {
        var (authorizedKeys, pemText) = GenerateEd25519KeyPair();

        Assert.True(SshEd25519Recipient.TryParse(authorizedKeys, out var recipient));
        Assert.NotNull(recipient);

        Assert.True(SshEd25519Identity.TryParse(pemText, out var identity));
        identity.Dispose();
    }

    [Fact]
    public void SshRsa_TryParse_Valid_Succeeds()
    {
        var (authorizedKeys, pemText) = GenerateRsaKeyPair(2048);

        Assert.True(SshRsaRecipient.TryParse(authorizedKeys, out var recipient));
        Assert.NotNull(recipient);

        Assert.True(SshRsaIdentity.TryParse(pemText, out var identity));
        identity.Dispose();
    }

    // --- SSH types: malformed input returns false, never throws ---

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ssh-ed25519")]                       // missing key field
    [InlineData("ssh-ed25519 !!!notbase64!!!")]       // invalid base64
    [InlineData("ssh-ed25519 AAAA")]                  // valid base64, garbage blob
    [InlineData("ssh-dss AAAAB3NzaC1kc3M ignored")]   // unsupported type
    public void SshEd25519Recipient_TryParse_Malformed_ReturnsFalse(string? input)
    {
        Assert.False(SshEd25519Recipient.TryParse(input, out var result));
        Assert.Null(result);
    }

    [Fact]
    public void SshEd25519Recipient_TryParse_TypeMismatchedBlob_ReturnsFalse()
    {
        // Declares ssh-ed25519 but carries an ssh-rsa wire blob
        var (rsaLine, _) = GenerateRsaKeyPair(2048);
        var rsaBlob = rsaLine.Split(' ')[1];

        Assert.False(SshEd25519Recipient.TryParse($"ssh-ed25519 {rsaBlob}", out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("no pem here")]
    [InlineData("BEGIN OPENSSH PRIVATE KEY")]         // marker without PEM structure
    public void SshEd25519Identity_TryParse_Malformed_ReturnsFalse(string? input)
    {
        Assert.False(SshEd25519Identity.TryParse(input, out var result));
        Assert.Null(result);
    }

    [Fact]
    public void SshEd25519Identity_TryParse_GarbageOpenSshBlob_ReturnsFalse()
    {
        // Well-formed PEM armor around a blob BouncyCastle cannot parse
        var pem = BuildOpenSshPem(new byte[64]);
        Assert.False(SshEd25519Identity.TryParse(pem, out _));
    }

    [Fact]
    public void SshEd25519Identity_TryParse_RsaPem_ReturnsFalse()
    {
        var (_, rsaPem) = GenerateRsaKeyPair(2048);
        Assert.False(SshEd25519Identity.TryParse(rsaPem, out _));
    }

    [Fact]
    public void SshRsaRecipient_TryParse_WeakKey_ReturnsFalse()
    {
        var (authorizedKeys, _) = GenerateRsaKeyPair(1024);
        Assert.False(SshRsaRecipient.TryParse(authorizedKeys, out _));
    }

    [Fact]
    public void SshRsaRecipient_TryParse_TypeMismatchedBlob_ReturnsFalse()
    {
        // Declares ssh-rsa but carries an ssh-ed25519 wire blob
        var (ed25519Line, _) = GenerateEd25519KeyPair();
        var ed25519Blob = ed25519Line.Split(' ')[1];

        Assert.False(SshRsaRecipient.TryParse($"ssh-rsa {ed25519Blob}", out _));
    }

    [Fact]
    public void SshRsaIdentity_TryParse_StructurallyBrokenPem_ReturnsFalse()
    {
        // Valid markers around content the PEM reader chokes on (not base64)
        var broken = "-----BEGIN RSA PRIVATE KEY-----\nnot base64 at all !!!\n-----END RSA PRIVATE KEY-----\n";
        Assert.False(SshRsaIdentity.TryParse(broken, out _));
    }

    [Fact]
    public void SshRsaIdentity_TryParse_Ed25519Pem_ReturnsFalse()
    {
        var (_, ed25519Pem) = GenerateEd25519KeyPair();
        Assert.False(SshRsaIdentity.TryParse(ed25519Pem, out _));
    }

    // --- declared-vs-actual key type mismatch (each Parse rejects the other's key) ---

    [Fact]
    public void SshEd25519_Parse_RsaKey_ThrowsFormatException()
    {
        var (_, rsaPem) = GenerateRsaKeyPair(2048);

        var ex = Assert.Throws<AgeFormatException>(() => SshEd25519Identity.Parse(rsaPem));
        Assert.Contains("expected ssh-ed25519", ex.Message);
    }

    [Fact]
    public void SshRsa_Parse_Ed25519Key_ThrowsFormatException()
    {
        var (_, ed25519Pem) = GenerateEd25519KeyPair();

        var ex = Assert.Throws<AgeFormatException>(() => SshRsaIdentity.Parse(ed25519Pem));
        Assert.Contains("expected ssh-rsa", ex.Message);
    }

    // --- helpers (mirrors SshTests' generators) ---

    private static (string authorizedKeys, string pemText) GenerateEd25519KeyPair()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        var privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;

        var wireBytes = Org.BouncyCastle.Crypto.Utilities.OpenSshPublicKeyUtilities.EncodePublicKey(keyPair.Public);
        var authorizedKeys = $"ssh-ed25519 {Convert.ToBase64String(wireBytes)} test@example";

        var blob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(privateKey);
        return (authorizedKeys, BuildOpenSshPem(blob));
    }

    private static (string authorizedKeys, string pemText) GenerateRsaKeyPair(int bits)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), bits));
        var keyPair = generator.GenerateKeyPair();

        var wireBytes = Org.BouncyCastle.Crypto.Utilities.OpenSshPublicKeyUtilities.EncodePublicKey(keyPair.Public);
        var authorizedKeys = $"ssh-rsa {Convert.ToBase64String(wireBytes)} test@example";

        using var sw = new StringWriter();
        new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(keyPair.Private);
        return (authorizedKeys, sw.ToString());
    }

    private static string BuildOpenSshPem(byte[] blob)
    {
        var sb = new StringBuilder();
        var pemWriter = new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(new StringWriter(sb));
        pemWriter.WriteObject(new PemObject("OPENSSH PRIVATE KEY", blob));
        return sb.ToString();
    }
}
