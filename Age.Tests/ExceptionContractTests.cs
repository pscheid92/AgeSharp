using System.Text;
using Age.Crypto;
using Age.Format;
using Age.Recipients;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Pins the v0.3 exception contract: structure that can't be parsed throws
/// <see cref="AgeFormatException"/>; parsed structure whose cryptographic
/// checks fail throws <see cref="AgeAuthenticationException"/>; and every
/// library exception is catchable as <see cref="AgeException"/>.
/// </summary>
public class ExceptionContractTests
{
    // --- hierarchy: catch (AgeException) covers everything ---

    [Fact]
    public void All_Exception_Types_Derive_From_AgeException()
    {
        Assert.IsAssignableFrom<AgeException>(new AgeFormatException("m"));
        Assert.IsAssignableFrom<AgeException>(new AgeAuthenticationException("m"));
        Assert.IsAssignableFrom<AgeException>(new NoIdentityMatchException());
        Assert.IsAssignableFrom<AgeException>(new AgePluginException("m"));
    }

    [Fact]
    public void Inner_Exception_Constructors_Preserve_Cause()
    {
        var cause = new InvalidOperationException("root");

        var format = new AgeFormatException("f", cause);
        Assert.Equal("f", format.Message);
        Assert.Same(cause, format.InnerException);

        var auth = new AgeAuthenticationException("a", cause);
        Assert.Equal("a", auth.Message);
        Assert.Same(cause, auth.InnerException);

        var plugin = new AgePluginException("p", cause);
        Assert.Same(cause, plugin.InnerException);
    }

    // --- Format: structural defects in the payload framing ---

    [Fact]
    public void DecryptDetached_TruncatedPayloadNonce_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity);

        using var shortPayload = new MemoryStream(payload[..7]);
        using var headerInput = new MemoryStream(header);

        var ex = Assert.Throws<AgeFormatException>(() =>
            AgeEncrypt.DecryptDetached(headerInput, shortPayload, new MemoryStream(), identity));
        Assert.Contains("payload nonce", ex.Message);
    }

    [Fact]
    public void Identity_Returning_WrongSize_FileKey_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        using var encrypted = Encrypt(identity, "hello"u8.ToArray());

        var ex = Assert.Throws<AgeFormatException>(() =>
            AgeEncrypt.Decrypt(encrypted, new MemoryStream(), new WrongSizeIdentity()));
        Assert.Contains("file key must be", ex.Message);
    }

    // --- Authentication: defects in the payload region ---

    [Fact]
    public void RandomAccess_EmptyPayload_ThrowsAuthentication()
    {
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity);

        // header + nonce, zero chunks
        using var file = new MemoryStream([.. header, .. payload[..16]]);

        var ex = Assert.Throws<AgeAuthenticationException>(() => new AgeRandomAccess(file, identity));
        Assert.Contains("payload is empty", ex.Message);
    }

    [Fact]
    public void RandomAccess_PayloadShorterThanTag_ThrowsAuthentication()
    {
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity);

        // header + nonce + 5 bytes: a chunk cannot even hold its tag
        using var file = new MemoryStream([.. header, .. payload[..21]]);

        var ex = Assert.Throws<AgeAuthenticationException>(() => new AgeRandomAccess(file, identity));
        Assert.Contains("chunk too small", ex.Message);
    }

    [Fact]
    public void CorruptedChunk_ThrowsAuthentication()
    {
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity);

        payload[20] ^= 0x01; // flip one bit inside the first chunk (past the 16-byte nonce)
        using var headerInput = new MemoryStream(header);
        using var payloadInput = new MemoryStream(payload);

        Assert.Throws<AgeAuthenticationException>(() =>
            AgeEncrypt.DecryptDetached(headerInput, payloadInput, new MemoryStream(), identity));
    }

    [Fact]
    public void Stream_EmptyFinalChunk_AfterData_ThrowsAuthentication()
    {
        // STREAM rule: an empty final chunk is only legal for empty plaintext.
        // Forge the sequence with a known payload key via the internal API.
        var key = new byte[32];
        new Random(42).NextBytes(key);

        var full = StreamEncryption.EncryptChunk(key, 0, isFinal: false, new byte[StreamEncryption.ChunkSize]);
        var emptyFinal = StreamEncryption.EncryptChunk(key, 1, isFinal: true, []);

        using var input = new MemoryStream([.. full, .. emptyFinal]);
        var ex = Assert.Throws<AgeAuthenticationException>(() =>
            StreamEncryption.Decrypt(key, input, new MemoryStream()));
        Assert.Contains("final STREAM chunk is empty", ex.Message);
    }

    [Fact]
    public void Header_TruncatedAfterVersionLine_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream("age-encryption.org/v1\n"u8.ToArray());

        var ex = Assert.Throws<AgeFormatException>(() =>
            AgeEncrypt.Decrypt(input, new MemoryStream(), identity));
        Assert.Contains("unexpected end of header", ex.Message);
    }

    [Fact]
    public void Stanza_Parse_AtEndOfStream_ThrowsFormat()
    {
        var reader = new HeaderReader(new MemoryStream());
        var ex = Assert.Throws<AgeFormatException>(() => Stanza.Parse(reader));
        Assert.Contains("while reading stanza", ex.Message);
    }

    [Fact]
    public void DecryptChunk_ShorterThanTag_ThrowsAuthentication()
    {
        // The internal API's own guard: a chunk that cannot even hold its tag is
        // rejected before any cipher work.
        var key = new byte[32];
        Assert.Throws<AgeAuthenticationException>(() =>
            StreamEncryption.DecryptChunk(key, 0, isFinal: true, new byte[5]));
    }

    // --- Format: armor defects ---

    [Fact]
    public void Armor_NonCanonicalBase64_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        var armored = "-----BEGIN AGE ENCRYPTED FILE-----\nAB\n-----END AGE ENCRYPTED FILE-----\n";
        using var input = new MemoryStream(Encoding.ASCII.GetBytes(armored));

        Assert.Throws<AgeFormatException>(() =>
            AgeEncrypt.Decrypt(input, new MemoryStream(), identity));
    }

    [Fact]
    public void Armor_InvalidBase64Character_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        var armored = "-----BEGIN AGE ENCRYPTED FILE-----\n!!!!\n-----END AGE ENCRYPTED FILE-----\n";
        using var input = new MemoryStream(Encoding.ASCII.GetBytes(armored));

        Assert.Throws<AgeFormatException>(() =>
            AgeEncrypt.Decrypt(input, new MemoryStream(), identity));
    }

    [Fact]
    public void Armor_PaddingOnFullLine_ThrowsFormat()
    {
        // A 64-char line must decode to exactly 48 bytes; embedded padding decodes
        // successfully but is non-canonical.
        using var identity = X25519Identity.Generate();
        var body = new string('A', 62) + "==";
        var armored = $"-----BEGIN AGE ENCRYPTED FILE-----\n{body}\n-----END AGE ENCRYPTED FILE-----\n";
        using var input = new MemoryStream(Encoding.ASCII.GetBytes(armored));

        var ex = Assert.Throws<AgeFormatException>(() =>
            AgeEncrypt.Decrypt(input, new MemoryStream(), identity));
        Assert.Contains("non-canonical base64 in armor", ex.Message);
    }

    [Fact]
    public void Dearmor_BlankOnlyInput_ThrowsFormat()
    {
        using var input = new MemoryStream("  \n\n \n"u8.ToArray());
        var ex = Assert.Throws<AgeFormatException>(() => AsciiArmor.Dearmor(input));
        Assert.Contains("empty armored data", ex.Message);
    }

    // --- Format: encoding primitives ---

    [Fact]
    public void Bech32_InvalidDataCharacter_ThrowsFormat()
    {
        // 'b' is not in the bech32 charset; data part is long enough to reach the char scan
        var ex = Assert.Throws<AgeFormatException>(() => Bech32.Decode("age1bqqqqqq"));
        Assert.Contains("invalid bech32 character", ex.Message);
    }

    [Fact]
    public void Bech32_ExcessPadding_ThrowsFormat()
    {
        // One 5-bit group cannot carry any 8-bit bytes: all five bits are padding
        var ex = Assert.Throws<AgeFormatException>(() => Bech32.Decode(MakeBech32("age", [0])));
        Assert.Contains("excess padding", ex.Message);
    }

    [Fact]
    public void Bech32_NonZeroPaddingBits_ThrowsFormat()
    {
        // Two groups = 10 bits = one byte + 2 padding bits; value 1 leaves them non-zero
        var ex = Assert.Throws<AgeFormatException>(() => Bech32.Decode(MakeBech32("age", [0, 1])));
        Assert.Contains("non-zero padding", ex.Message);
    }

    // --- Format: SSH key material ---

    [Fact]
    public void SshIdentity_MarkerWithoutPem_ThrowsFormat()
    {
        var ex = Assert.Throws<AgeFormatException>(() =>
            AgeKeygen.ParseSshIdentity("BEGIN OPENSSH PRIVATE KEY"));
        Assert.Contains("failed to read PEM object", ex.Message);
    }

    [Fact]
    public void SshIdentity_UnsupportedKeyType_ThrowsFormat()
    {
        // A valid PEM private key of a type age does not support (EC)
        var generator = new ECKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 256));
        var keyPair = generator.GenerateKeyPair();

        using var sw = new StringWriter();
        new PemWriter(sw).WriteObject(keyPair.Private);

        var ex = Assert.Throws<AgeFormatException>(() => AgeKeygen.ParseSshIdentity(sw.ToString()));
        Assert.Contains("unsupported private key type", ex.Message);
    }

    // --- Format: key string parsing ---

    [Fact]
    public void PqIdentity_WrongSeedLength_ThrowsFormat()
    {
        var tooShort = Bech32.Encode("age-secret-key-pq-", new byte[16]).ToUpperInvariant();
        var ex = Assert.Throws<AgeFormatException>(() => MlKem768X25519Identity.Parse(tooShort));
        Assert.Contains("seed must be", ex.Message);
    }

    [Fact]
    public void PqRecipient_X25519Hrp_ThrowsFormat()
    {
        using var identity = X25519Identity.Generate();
        var x25519Recipient = identity.Recipient.ToString(); // valid bech32, HRP "age"

        var ex = Assert.Throws<AgeFormatException>(() => MlKem768X25519Recipient.Parse(x25519Recipient));
        Assert.Contains("expected HRP", ex.Message);
    }

    // --- helpers ---

    private sealed class WrongSizeIdentity : IIdentity
    {
        public byte[]? Unwrap(Stanza stanza) => new byte[5];
    }

    private static MemoryStream Encrypt(X25519Identity identity, byte[] plaintext)
    {
        var output = new MemoryStream();
        using var input = new MemoryStream(plaintext);
        AgeEncrypt.Encrypt(input, output, identity.Recipient);
        output.Position = 0;
        return output;
    }

    private static (byte[] Header, byte[] Payload) EncryptDetached(X25519Identity identity)
    {
        using var input = new MemoryStream("some plaintext for the contract tests"u8.ToArray());
        using var header = new MemoryStream();
        using var payload = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, header, payload, identity.Recipient);
        return (header.ToArray(), payload.ToArray());
    }

    // Minimal BIP-173 bech32 writer so tests can craft strings with valid
    // checksums but invalid data-part padding (the library's Encode can only
    // produce well-formed payloads).
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private static string MakeBech32(string hrp, byte[] data5)
    {
        var values = new List<byte>();
        foreach (var c in hrp) values.Add((byte)(c >> 5));
        values.Add(0);
        foreach (var c in hrp) values.Add((byte)(c & 31));
        values.AddRange(data5);
        values.AddRange(new byte[6]);

        var polymod = Polymod(values) ^ 1;
        var sb = new StringBuilder(hrp).Append('1');
        foreach (var d in data5) sb.Append(Charset[d]);
        for (var i = 0; i < 6; i++) sb.Append(Charset[(polymod >> (5 * (5 - i))) & 31]);
        return sb.ToString();
    }

    private static int Polymod(List<byte> values)
    {
        int[] generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        var chk = 1;
        foreach (var v in values)
        {
            var top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (var i = 0; i < 5; i++)
            {
                if (((top >> i) & 1) != 0)
                    chk ^= generator[i];
            }
        }
        return chk;
    }
}
