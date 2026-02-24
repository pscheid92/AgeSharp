using System.Text;
using Age;
using Age.Crypto;
using Age.Format;
using Age.Recipients;
using NSec.Cryptography;
using Xunit;

namespace Age.Tests;

public class Base64UnpaddedTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(48)]
    public void Encode_Decode_RoundTrip(int length)
    {
        var data = new byte[length];
        new Random(42).NextBytes(data);
        var encoded = Base64Unpadded.Encode(data);
        var decoded = Base64Unpadded.Decode(encoded);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Empty_Input_Returns_Empty()
    {
        Assert.Equal("", Base64Unpadded.Encode(ReadOnlySpan<byte>.Empty));
        Assert.Empty(Base64Unpadded.Decode(ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void Padding_Characters_Rejected()
    {
        var ex = Assert.Throws<FormatException>(() => Base64Unpadded.Decode("AAAA=="));
        Assert.Contains("padding", ex.Message);
    }

    [Fact]
    public void NonCanonical_Encoding_Rejected()
    {
        // "AB" decodes to 1 byte (0x00), but canonical encoding of 0x00 is "AA"
        var ex = Assert.Throws<FormatException>(() => Base64Unpadded.Decode("AB"));
        Assert.Contains("non-canonical", ex.Message);
    }

    [Fact]
    public void Invalid_Characters_Rejected()
    {
        Assert.Throws<FormatException>(() => Base64Unpadded.Decode("@@@@"));
    }

    [Fact]
    public void Encode_Large_Data_Uses_Heap_Buffer()
    {
        // > 256 chars of base64 output triggers the heap-allocated path
        var data = new byte[200];
        new Random(42).NextBytes(data);
        var encoded = Base64Unpadded.Encode(data);
        var decoded = Base64Unpadded.Decode(encoded);
        Assert.Equal(data, decoded);
    }
}

public class Bech32Tests
{
    [Fact]
    public void Encode_Decode_RoundTrip()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        var encoded = Bech32.Encode("age", data);
        var (hrp, decoded) = Bech32.Decode(encoded);
        Assert.Equal("age", hrp);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Known_Recipient_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        Assert.StartsWith("age1", recipientStr);
        var parsed = X25519Recipient.Parse(recipientStr);
        Assert.Equal(recipientStr, parsed.ToString());
    }

    [Fact]
    public void Mixed_Case_Rejected()
    {
        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();
        // Force mixed case
        var mixed = recipientStr[..4] + recipientStr[4..].ToUpperInvariant();
        Assert.Throws<FormatException>(() => Bech32.Decode(mixed));
    }

    [Fact]
    public void Invalid_Checksum_Rejected()
    {
        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();
        // Flip last character
        var chars = recipientStr.ToCharArray();
        chars[^1] = chars[^1] == 'q' ? 'p' : 'q';
        Assert.Throws<FormatException>(() => Bech32.Decode(new string(chars)));
    }

    [Fact]
    public void Invalid_Character_Rejected()
    {
        Assert.Throws<FormatException>(() => Bech32.Decode("age1b"));
    }
}

public class HeaderReaderTests
{
    [Fact]
    public void Reads_LF_Terminated_Lines()
    {
        var stream = new MemoryStream("hello\nworld\n"u8.ToArray());
        var reader = new HeaderReader(stream);
        Assert.Equal("hello", reader.ReadLine());
        Assert.Equal("world", reader.ReadLine());
    }

    [Fact]
    public void Returns_Null_At_EOF_On_Empty_Stream()
    {
        var stream = new MemoryStream(Array.Empty<byte>());
        var reader = new HeaderReader(stream);
        Assert.Null(reader.ReadLine());
    }

    [Fact]
    public void Throws_On_CR()
    {
        var stream = new MemoryStream("hello\r\n"u8.ToArray());
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => reader.ReadLine());
    }

    [Fact]
    public void Throws_On_NonAscii()
    {
        var stream = new MemoryStream(new byte[] { 0x80, 0x0A });
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => reader.ReadLine());
    }

    [Fact]
    public void PushBack_Returns_Pushed_Line_Then_Resumes()
    {
        var stream = new MemoryStream("line2\n"u8.ToArray());
        var reader = new HeaderReader(stream);
        reader.PushBack("line1");
        Assert.Equal("line1", reader.ReadLine());
        Assert.Equal("line2", reader.ReadLine());
    }

    [Fact]
    public void RawBytes_Tracks_All_Bytes_Read()
    {
        var content = "abc\ndef\n"u8.ToArray();
        var stream = new MemoryStream(content);
        var reader = new HeaderReader(stream);
        reader.ReadLine();
        reader.ReadLine();
        Assert.Equal(content, reader.RawBytes.ToArray());
    }

    [Fact]
    public void ReadPayloadBytes_Reads_Exact_Count()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var stream = new MemoryStream(data);
        var reader = new HeaderReader(stream);
        var buf = new byte[3];
        int read = reader.ReadPayloadBytes(buf);
        Assert.Equal(3, read);
        Assert.Equal(new byte[] { 1, 2, 3 }, buf);
    }

    [Fact]
    public void Throws_On_EOF_Without_Trailing_Newline()
    {
        // Partial line with no \n triggers "unexpected end of stream"
        var stream = new MemoryStream("hello"u8.ToArray());
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => reader.ReadLine());
    }
}

public class StanzaTests
{
    [Fact]
    public void Parse_Valid_Stanza_With_Args_And_Body()
    {
        var text = "-> X25519 abc123\ndGVzdA\n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        var stanza = Stanza.Parse(reader);
        Assert.Equal("X25519", stanza.Type);
        Assert.Single(stanza.Args);
        Assert.Equal("abc123", stanza.Args[0]);
        Assert.Equal("test"u8.ToArray(), stanza.Body);
    }

    [Fact]
    public void Parse_Stanza_With_Empty_Body()
    {
        var text = "-> scrypt salt 18\n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        var stanza = Stanza.Parse(reader);
        Assert.Equal("scrypt", stanza.Type);
        Assert.Equal(new[] { "salt", "18" }, stanza.Args);
        Assert.Empty(stanza.Body);
    }

    [Fact]
    public void Parse_Stanza_With_MultiLine_Body()
    {
        // 48 bytes encodes to 64 base64 chars (exactly one full line), requiring a short/empty final line
        var body = new byte[48];
        new Random(42).NextBytes(body);
        var encoded = Base64Unpadded.Encode(body);
        Assert.Equal(64, encoded.Length);
        var text = $"-> test\n{encoded}\n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        var stanza = Stanza.Parse(reader);
        Assert.Equal(body, stanza.Body);
    }

    [Fact]
    public void Reject_Missing_Arrow_Prefix()
    {
        var text = "X25519 abc\ndata\n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Stanza.Parse(reader));
    }

    [Fact]
    public void Reject_Body_Line_Exceeding_64_Characters()
    {
        var longLine = new string('A', 65);
        var text = $"-> test\n{longLine}\n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Stanza.Parse(reader));
    }

    [Fact]
    public void WriteTo_Parse_RoundTrip()
    {
        var body = new byte[50];
        new Random(42).NextBytes(body);
        var original = new Stanza("X25519", new[] { "argA", "argB" }, body);

        using var ms = new MemoryStream();
        original.WriteTo(ms);
        ms.Position = 0;
        var reader = new HeaderReader(ms);
        var parsed = Stanza.Parse(reader);

        Assert.Equal(original.Type, parsed.Type);
        Assert.Equal(original.Args, parsed.Args);
        Assert.Equal(original.Body, parsed.Body);
    }

    [Fact]
    public void WriteTo_Empty_Body_RoundTrips()
    {
        var original = new Stanza("test", Array.Empty<string>(), Array.Empty<byte>());
        using var ms = new MemoryStream();
        original.WriteTo(ms);
        ms.Position = 0;
        var reader = new HeaderReader(ms);
        var parsed = Stanza.Parse(reader);
        Assert.Empty(parsed.Body);
    }

    [Fact]
    public void WriteTo_ExactMultipleOf64_Body_RoundTrips()
    {
        // 48 bytes → exactly 64 base64 chars → needs trailing empty line
        var body = new byte[48];
        new Random(42).NextBytes(body);
        var original = new Stanza("test", Array.Empty<string>(), body);
        using var ms = new MemoryStream();
        original.WriteTo(ms);
        ms.Position = 0;
        var reader = new HeaderReader(ms);
        var parsed = Stanza.Parse(reader);
        Assert.Equal(body, parsed.Body);
    }

    [Fact]
    public void Reject_Empty_Stanza_Type()
    {
        // "-> \n" means the rest after "-> " is empty → split gives [""]
        var text = "-> \n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Stanza.Parse(reader));
    }

    [Fact]
    public void Reject_EOF_During_Body_Read()
    {
        var text = "-> test\n";  // no body lines at all, EOF
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Stanza.Parse(reader));
    }

    [Fact]
    public void Reject_Invalid_Character_In_Type()
    {
        var text = "-> te\x01st\n\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Stanza.Parse(reader));
    }
}

public class HeaderTests
{
    [Fact]
    public void Parse_Valid_Header_With_MAC()
    {
        // Build a valid header by writing one, then parsing it back
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        var header = new Header();
        header.Stanzas.Add(new Stanza("X25519", new[] { "ephemeralkey" }, new byte[32]));

        using var ms = new MemoryStream();
        header.WriteTo(ms, fileKey);

        ms.Position = 0;
        var reader = new HeaderReader(ms);
        var parsed = Header.Parse(reader);

        Assert.Single(parsed.Stanzas);
        Assert.Equal(32, parsed.Mac.Length);
        parsed.VerifyMac(fileKey);
    }

    [Fact]
    public void Reject_Wrong_Version_Line()
    {
        var text = "age-encryption.org/v2\n-> test\n\n--- AAAA\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
    }

    [Fact]
    public void Reject_Header_With_No_Stanzas()
    {
        // MAC line immediately after version
        var macBytes = new byte[32];
        var macB64 = Base64Unpadded.Encode(macBytes);
        var text = $"age-encryption.org/v1\n--- {macB64}\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
    }

    [Fact]
    public void ComputeMac_Deterministic()
    {
        var fileKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var headerBytes = "age-encryption.org/v1\n-> test\n\n---"u8.ToArray();

        var mac1 = Header.ComputeMac(fileKey, headerBytes);
        var mac2 = Header.ComputeMac(fileKey, headerBytes);

        Assert.Equal(mac1, mac2);
        Assert.Equal(32, mac1.Length);
    }

    [Fact]
    public void WriteTo_Parse_RoundTrip_With_MAC_Verification()
    {
        var fileKey = new byte[16];
        new Random(123).NextBytes(fileKey);

        var header = new Header();
        header.Stanzas.Add(new Stanza("X25519", new[] { "arg1" }, new byte[32]));
        header.Stanzas.Add(new Stanza("X25519", new[] { "arg2" }, new byte[32]));

        using var ms = new MemoryStream();
        header.WriteTo(ms, fileKey);

        ms.Position = 0;
        var reader = new HeaderReader(ms);
        var parsed = Header.Parse(reader);

        Assert.Equal(2, parsed.Stanzas.Count);
        parsed.VerifyMac(fileKey); // Should not throw
    }

    [Fact]
    public void Reject_Invalid_MAC_Encoding()
    {
        var text = "age-encryption.org/v1\n-> test\n\n--- @@@invalid\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
    }

    [Fact]
    public void Reject_MAC_Wrong_Length()
    {
        // 16 bytes instead of 32
        var shortMac = Base64Unpadded.Encode(new byte[16]);
        var text = $"age-encryption.org/v1\n-> test\n\n--- {shortMac}\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
    }

    [Fact]
    public void Reject_Footer_Without_Space()
    {
        // "---\n" with no space before MAC
        var text = "age-encryption.org/v1\n-> test\n\n---\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
    }

    [Fact]
    public void Reject_Unexpected_Line_In_Header()
    {
        var macB64 = Base64Unpadded.Encode(new byte[32]);
        var text = $"age-encryption.org/v1\n-> test\n\nbogus line\n--- {macB64}\n";
        var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        var reader = new HeaderReader(stream);
        Assert.Throws<AgeHeaderException>(() => Header.Parse(reader));
    }

    [Fact]
    public void VerifyMac_Rejects_Wrong_Key()
    {
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        var header = new Header();
        header.Stanzas.Add(new Stanza("X25519", new[] { "arg" }, new byte[32]));

        using var ms = new MemoryStream();
        header.WriteTo(ms, fileKey);

        ms.Position = 0;
        var reader = new HeaderReader(ms);
        var parsed = Header.Parse(reader);

        var wrongKey = new byte[16];
        new Random(99).NextBytes(wrongKey);
        Assert.Throws<AgeHmacException>(() => parsed.VerifyMac(wrongKey));
    }
}

public class AsciiArmorTests
{
    [Fact]
    public void Armor_Dearmor_RoundTrip()
    {
        var data = new byte[100];
        new Random(42).NextBytes(data);

        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        armored.Position = 0;
        using var dearmored = AsciiArmor.Dearmor(armored);
        Assert.Equal(data, dearmored.ToArray());
    }

    [Fact]
    public void IsArmored_Detects_Armored_Input()
    {
        var data = new byte[10];
        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        armored.Position = 0;
        Assert.True(AsciiArmor.IsArmored(armored));
    }

    [Fact]
    public void IsArmored_Returns_False_For_Binary_Input()
    {
        var data = new byte[] { 0x00, 0x01, 0x02, 0x03 };
        using var stream = new MemoryStream(data);
        Assert.False(AsciiArmor.IsArmored(stream));
    }

    [Fact]
    public void Reject_Missing_Begin_Marker()
    {
        var text = "not a marker\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Reject_Missing_End_Marker()
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\nAAAA\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Reject_Trailing_NonWhitespace_Data()
    {
        var data = new byte[10];
        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        // Append trailing non-whitespace
        armored.Write("extra"u8);
        armored.Position = 0;
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(armored));
    }

    [Fact]
    public void Reject_Empty_Body_Lines()
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Dearmor_Skips_Leading_Whitespace()
    {
        var data = new byte[10];
        new Random(42).NextBytes(data);
        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        // Prepend whitespace
        var armoredBytes = armored.ToArray();
        var withWs = new byte[3 + armoredBytes.Length];
        withWs[0] = (byte)' ';
        withWs[1] = (byte)'\n';
        withWs[2] = (byte)'\t';
        armoredBytes.CopyTo(withWs, 3);

        using var wsStream = new MemoryStream(withWs);
        using var dearmored = AsciiArmor.Dearmor(wsStream);
        Assert.Equal(data, dearmored.ToArray());
    }

    [Fact]
    public void IsArmored_With_Leading_Whitespace()
    {
        var data = new byte[10];
        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        var armoredBytes = armored.ToArray();
        var withWs = new byte[2 + armoredBytes.Length];
        withWs[0] = (byte)' ';
        withWs[1] = (byte)'\n';
        armoredBytes.CopyTo(withWs, 2);

        using var wsStream = new MemoryStream(withWs);
        Assert.True(AsciiArmor.IsArmored(wsStream));
    }

    [Fact]
    public void Reject_Whitespace_In_Body_Line()
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n AAAA\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Reject_Body_Line_Over_64_Characters()
    {
        var longLine = new string('A', 68); // > 64
        var text = $"-----BEGIN AGE ENCRYPTED FILE-----\n{longLine}\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Reject_Short_Line_Not_Last()
    {
        // Short line followed by another body line
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\nAA==\nAAAA\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Reject_Invalid_Base64_Character_In_Body()
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n@@@@\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Reject_NonCanonical_Base64_In_Body()
    {
        // "AAAB" decodes to [0,0,1], but we encode with trailing bits set differently
        // Use "AAA=" which decodes to [0,0] — canonical for [0,0] is "AAA="
        // Instead: "Aa==" decodes to a byte, but canonical is something else
        // Simplest: use a padded string that re-encodes differently
        // "AQ==" is canonical for [1]. "AR==" decodes to [1] as well? No.
        // Let's try: "AB==" → decodes to [0], canonical for [0] is "AA=="
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\nAB==\n-----END AGE ENCRYPTED FILE-----\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        Assert.Throws<AgeArmorException>(() => AsciiArmor.Dearmor(stream));
    }

    [Fact]
    public void Dearmor_Handles_CRLF()
    {
        var data = new byte[10];
        new Random(42).NextBytes(data);
        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        // Replace \n with \r\n
        var armoredStr = Encoding.ASCII.GetString(armored.ToArray());
        var crlfStr = armoredStr.Replace("\n", "\r\n");
        using var crlfStream = new MemoryStream(Encoding.ASCII.GetBytes(crlfStr));
        using var dearmored = AsciiArmor.Dearmor(crlfStream);
        Assert.Equal(data, dearmored.ToArray());
    }

    [Fact]
    public void Allows_Trailing_Whitespace_After_End()
    {
        var data = new byte[10];
        new Random(42).NextBytes(data);
        using var input = new MemoryStream(data);
        using var armored = new MemoryStream();
        AsciiArmor.Armor(input, armored);

        armored.Write("\n  \n"u8);
        armored.Position = 0;
        using var dearmored = AsciiArmor.Dearmor(armored);
        Assert.Equal(data, dearmored.ToArray());
    }
}

public class StreamEncryptionTests
{
    private static byte[] MakePayloadKey()
    {
        // Derive a valid payload key via HKDF like the real code does
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);
        var nonce = new byte[16];
        new Random(43).NextBytes(nonce);

        var hkdf = NSec.Cryptography.KeyDerivationAlgorithm.HkdfSha256;
        return hkdf.DeriveBytes(fileKey, nonce, Encoding.ASCII.GetBytes("payload"), 32);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(64 * 1024)]
    [InlineData(64 * 1024 + 1)]
    public void Encrypt_Decrypt_RoundTrip(int size)
    {
        var payloadKey = MakePayloadKey();
        var plaintext = new byte[size];
        new Random(44).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        StreamEncryption.Encrypt(payloadKey, encInput, encOutput);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        StreamEncryption.Decrypt(payloadKey, encOutput, decOutput);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void Decrypt_Rejects_Empty_Payload()
    {
        var payloadKey = MakePayloadKey();
        using var input = new MemoryStream(Array.Empty<byte>());
        using var output = new MemoryStream();
        Assert.Throws<AgePayloadException>(() => StreamEncryption.Decrypt(payloadKey, input, output));
    }

    [Fact]
    public void Decrypt_Rejects_Truncated_Chunk()
    {
        var payloadKey = MakePayloadKey();
        // Less than 16 bytes (tag size)
        var data = new byte[10];
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        Assert.Throws<AgePayloadException>(() => StreamEncryption.Decrypt(payloadKey, input, output));
    }

    [Fact]
    public void Decrypt_Rejects_Corrupted_Ciphertext()
    {
        var payloadKey = MakePayloadKey();
        var plaintext = "test data"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        StreamEncryption.Encrypt(payloadKey, encInput, encOutput);

        var ciphertext = encOutput.ToArray();
        ciphertext[0] ^= 0xFF; // Flip a bit

        using var decInput = new MemoryStream(ciphertext);
        using var decOutput = new MemoryStream();
        Assert.Throws<AgePayloadException>(() => StreamEncryption.Decrypt(payloadKey, decInput, decOutput));
    }

    [Fact]
    public void Decrypt_Rejects_Data_After_Final_Chunk()
    {
        var payloadKey = MakePayloadKey();
        // Use >64K plaintext so we get at least 2 chunks (non-final + final)
        var plaintext = new byte[64 * 1024 + 100];
        new Random(44).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        StreamEncryption.Encrypt(payloadKey, encInput, encOutput);

        // Append extra data after the valid final chunk
        var ciphertext = encOutput.ToArray();
        var extended = new byte[ciphertext.Length + 64 * 1024 + 20];
        ciphertext.CopyTo(extended, 0);
        new Random(42).NextBytes(extended.AsSpan(ciphertext.Length));

        using var decInput = new MemoryStream(extended);
        using var decOutput = new MemoryStream();
        Assert.Throws<AgePayloadException>(() => StreamEncryption.Decrypt(payloadKey, decInput, decOutput));
    }

    [Fact]
    public void Decrypt_Rejects_NonFinal_Chunk_Wrong_Size()
    {
        var payloadKey = MakePayloadKey();
        // Encrypt >64K so we get a non-final chunk
        var plaintext = new byte[64 * 1024 + 100];
        new Random(42).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        StreamEncryption.Encrypt(payloadKey, encInput, encOutput);

        // Truncate in the middle of the first chunk — makes remaining > EncryptedChunkSize false
        // but chunkLen != EncryptedChunkSize. We need remaining > EncryptedChunkSize to be false
        // with chunkLen < EncryptedChunkSize and isFinal true, but that's valid.
        // Instead: just provide exactly EncryptedChunkSize + 1 bytes. The first chunk will be
        // EncryptedChunkSize (non-final), the second will be 1 byte (< TagSize).
        var badData = new byte[64 * 1024 + 16 + 1]; // EncryptedChunkSize + 1
        new Random(42).NextBytes(badData);

        using var decInput = new MemoryStream(badData);
        using var decOutput = new MemoryStream();
        Assert.Throws<AgePayloadException>(() => StreamEncryption.Decrypt(payloadKey, decInput, decOutput));
    }
}

public class ScryptRecipientTests
{
    [Theory]
    [InlineData("1", true, 1)]
    [InlineData("18", true, 18)]
    [InlineData("20", true, 20)]
    public void ValidateWorkFactor_Valid_Values(string input, bool expectedValid, int expectedValue)
    {
        bool result = ScryptRecipient.ValidateWorkFactor(input, out int workFactor);
        Assert.Equal(expectedValid, result);
        Assert.Equal(expectedValue, workFactor);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("")]
    [InlineData("-1")]
    [InlineData("abc")]
    public void ValidateWorkFactor_Invalid_Values(string input)
    {
        Assert.False(ScryptRecipient.ValidateWorkFactor(input, out _));
    }

    [Fact]
    public void Unwrap_Rejects_WorkFactor_Over_20()
    {
        var recipient = new ScryptRecipient("password");
        var salt = new byte[16];
        var saltB64 = Base64Unpadded.Encode(salt);
        var stanza = new Stanza("scrypt", new[] { saltB64, "21" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => recipient.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Wrong_Salt_Size()
    {
        var recipient = new ScryptRecipient("password");
        var wrongSalt = new byte[10];
        var saltB64 = Base64Unpadded.Encode(wrongSalt);
        var stanza = new Stanza("scrypt", new[] { saltB64, "10" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => recipient.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Wrong_Body_Size()
    {
        var recipient = new ScryptRecipient("password");
        var salt = new byte[16];
        var saltB64 = Base64Unpadded.Encode(salt);
        var stanza = new Stanza("scrypt", new[] { saltB64, "10" }, new byte[16]);
        Assert.Throws<AgeHeaderException>(() => recipient.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Wrong_Arg_Count()
    {
        var recipient = new ScryptRecipient("password");
        var stanza = new Stanza("scrypt", new[] { "onlyone" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => recipient.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Invalid_Salt_Encoding()
    {
        var recipient = new ScryptRecipient("password");
        var stanza = new Stanza("scrypt", new[] { "@@invalid@@", "10" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => recipient.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Invalid_WorkFactor_String()
    {
        var recipient = new ScryptRecipient("password");
        var salt = new byte[16];
        var saltB64 = Base64Unpadded.Encode(salt);
        var stanza = new Stanza("scrypt", new[] { saltB64, "abc" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => recipient.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_With_Wrong_Passphrase()
    {
        // Encrypt with one passphrase, try to decrypt with another
        var correct = new ScryptRecipient("correct", workFactor: 10);
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);
        var stanza = correct.Wrap(fileKey);

        var wrong = new ScryptRecipient("wrong", workFactor: 10);
        // Wrong passphrase causes AEAD failure — either throws AgeException or returns null
        try
        {
            var result = wrong.Unwrap(stanza);
            // If it didn't throw, result should be null (AEAD auth failure)
            Assert.Null(result);
        }
        catch (AgeException)
        {
            // Also acceptable — the code catches CryptographicException and rethrows as AgeException
        }
    }

    [Fact]
    public void Unwrap_Returns_Null_For_NonMatching_Type()
    {
        var recipient = new ScryptRecipient("password");
        var stanza = new Stanza("X25519", new[] { "arg" }, new byte[32]);
        Assert.Null(recipient.Unwrap(stanza));
    }
}

public class X25519RecipientIdentityTests
{
    [Fact]
    public void Recipient_Parse_ToString_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();
        var parsed = X25519Recipient.Parse(recipientStr);
        Assert.Equal(recipientStr, parsed.ToString());
    }

    [Fact]
    public void Identity_Parse_ToString_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var identityStr = identity.ToString();
        using var parsed = X25519Identity.Parse(identityStr);
        Assert.Equal(identityStr, parsed.ToString());
    }

    [Fact]
    public void Recipient_Reject_NonLowercase()
    {
        using var identity = X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString().ToUpperInvariant();
        Assert.Throws<FormatException>(() => X25519Recipient.Parse(recipientStr));
    }

    [Fact]
    public void Identity_Reject_NonUppercase()
    {
        using var identity = X25519Identity.Generate();
        var identityStr = identity.ToString().ToLowerInvariant();
        Assert.Throws<FormatException>(() => X25519Identity.Parse(identityStr));
    }

    [Fact]
    public void Recipient_Reject_Wrong_HRP()
    {
        var data = new byte[32];
        var encoded = Bech32.Encode("wrong", data);
        Assert.Throws<FormatException>(() => X25519Recipient.Parse(encoded));
    }

    [Fact]
    public void Identity_Reject_Wrong_HRP()
    {
        var data = new byte[32];
        var encoded = Bech32.Encode("WRONG-KEY-", data).ToUpperInvariant();
        Assert.Throws<FormatException>(() => X25519Identity.Parse(encoded));
    }

    [Fact]
    public void Unwrap_Returns_Null_For_NonMatching_StanzaType()
    {
        using var identity = X25519Identity.Generate();
        var stanza = new Stanza("scrypt", new[] { "arg" }, new byte[32]);
        Assert.Null(identity.Unwrap(stanza));
    }

    [Fact]
    public void Recipient_Reject_Wrong_Key_Length()
    {
        // 16 bytes instead of 32
        var encoded = Bech32.Encode("age", new byte[16]);
        Assert.Throws<FormatException>(() => X25519Recipient.Parse(encoded));
    }

    [Fact]
    public void Identity_Reject_Wrong_Key_Length()
    {
        var encoded = Bech32.Encode("AGE-SECRET-KEY-", new byte[16]).ToUpperInvariant();
        Assert.Throws<FormatException>(() => X25519Identity.Parse(encoded));
    }

    [Fact]
    public void Unwrap_Rejects_Wrong_Arg_Count()
    {
        using var identity = X25519Identity.Generate();
        var stanza = new Stanza("X25519", new[] { "a", "b" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Invalid_EphKey_Encoding()
    {
        using var identity = X25519Identity.Generate();
        var stanza = new Stanza("X25519", new[] { "@@invalid" }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Wrong_EphKey_Length()
    {
        using var identity = X25519Identity.Generate();
        var shortKey = Base64Unpadded.Encode(new byte[16]);
        var stanza = new Stanza("X25519", new[] { shortKey }, new byte[32]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Rejects_Wrong_Body_Length()
    {
        using var identity = X25519Identity.Generate();
        var ephKey = Base64Unpadded.Encode(new byte[32]);
        var stanza = new Stanza("X25519", new[] { ephKey }, new byte[16]);
        Assert.Throws<AgeHeaderException>(() => identity.Unwrap(stanza));
    }

    [Fact]
    public void Unwrap_Returns_Null_For_Wrong_Recipient()
    {
        // Encrypt to one identity, try to unwrap with another
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();

        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);
        var stanza = id1.Recipient.Wrap(fileKey);

        // id2 should fail AEAD and return null
        Assert.Null(id2.Unwrap(stanza));
    }
}

public class AgeEncryptTests
{
    [Fact]
    public void Encrypt_Rejects_No_Recipients()
    {
        using var input = new MemoryStream("test"u8.ToArray());
        using var output = new MemoryStream();
        Assert.Throws<ArgumentException>(() => AgeEncrypt.Encrypt(input, output));
    }

    [Fact]
    public void Armored_Encrypt_Decrypt_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "armored test"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, armor: true, identity.Recipient);

        // Verify it's actually armored
        encOutput.Position = 0;
        Assert.True(AsciiArmor.IsArmored(encOutput));

        // Decrypt
        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);
        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void Decrypt_Rejects_No_Matching_Identity()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();

        var plaintext = "test"u8.ToArray();
        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, id1.Recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Assert.Throws<NoIdentityMatchException>(() => AgeEncrypt.Decrypt(encOutput, decOutput, id2));
    }

    [Fact]
    public void Decrypt_Rejects_Scrypt_With_Multiple_Stanzas()
    {
        // Build a header manually with scrypt + X25519 stanzas
        using var id = X25519Identity.Generate();
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        var scryptRecipient = new ScryptRecipient("pass", workFactor: 10);
        var scryptStanza = scryptRecipient.Wrap(fileKey);
        var x25519Stanza = id.Recipient.Wrap(fileKey);

        var header = new Header();
        header.Stanzas.Add(scryptStanza);
        header.Stanzas.Add(x25519Stanza);

        using var ms = new MemoryStream();
        header.WriteTo(ms, fileKey);

        // Write payload nonce + encrypted payload
        var payloadNonce = new byte[16];
        ms.Write(payloadNonce);
        var hkdf = KeyDerivationAlgorithm.HkdfSha256;
        var payloadKey = hkdf.DeriveBytes(fileKey, payloadNonce, Encoding.ASCII.GetBytes("payload"), 32);
        StreamEncryption.Encrypt(payloadKey, new MemoryStream(Array.Empty<byte>()), ms);

        ms.Position = 0;
        using var output = new MemoryStream();
        Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(ms, output, scryptRecipient));
    }

    [Fact]
    public void Decrypt_Wraps_FormatException_From_Header()
    {
        // A FormatException during header parse should be wrapped in AgeHeaderException
        // Produce a header with invalid base64 in a stanza body, which triggers FormatException
        // via Base64Unpadded.Decode inside Stanza.Parse
        var text = "age-encryption.org/v1\n-> test\n@@@@\n\n--- AAAA\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        using var output = new MemoryStream();
        using var id = X25519Identity.Generate();
        var ex = Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(stream, output, id));
        Assert.Contains("header parse error", ex.Message);
    }

    [Fact]
    public void Decrypt_Rethrows_AgeHeaderException_From_Parse()
    {
        // Wrong version triggers AgeHeaderException directly from Header.Parse
        var text = "age-encryption.org/v2\n-> test\n\n--- AAAA\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(text));
        using var output = new MemoryStream();
        using var id = X25519Identity.Generate();
        Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(stream, output, id));
    }

    [Fact]
    public void Decrypt_Rethrows_AgeException_From_Unwrap()
    {
        // Build a valid header where X25519 stanza has wrong arg count,
        // causing Unwrap to throw AgeHeaderException
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        // Stanza with type X25519 but 2 args (expects 1) → Unwrap throws
        var badStanza = new Stanza("X25519", new[] { "arg1", "arg2" }, new byte[32]);
        var header = new Header();
        header.Stanzas.Add(badStanza);

        using var ms = new MemoryStream();
        header.WriteTo(ms, fileKey);
        // Append a payload nonce + minimal encrypted payload
        ms.Write(new byte[16]); // nonce
        var hkdf = KeyDerivationAlgorithm.HkdfSha256;
        var payloadKey = hkdf.DeriveBytes(fileKey, new byte[16], Encoding.ASCII.GetBytes("payload"), 32);
        StreamEncryption.Encrypt(payloadKey, new MemoryStream(Array.Empty<byte>()), ms);

        ms.Position = 0;
        using var output = new MemoryStream();
        using var id = X25519Identity.Generate();
        Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(ms, output, id));
    }

    [Fact]
    public void Decrypt_Rejects_Truncated_Nonce()
    {
        // Valid header but stream ends before 16-byte payload nonce
        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        using var id = X25519Identity.Generate();
        var stanza = id.Recipient.Wrap(fileKey);
        var header = new Header();
        header.Stanzas.Add(stanza);

        using var ms = new MemoryStream();
        header.WriteTo(ms, fileKey);
        // Write only 5 bytes of nonce (truncated)
        ms.Write(new byte[5]);

        ms.Position = 0;
        using var output = new MemoryStream();
        Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(ms, output, id));
    }
}

public class AgeKeygenTests
{
    [Fact]
    public void Generate_Returns_Valid_Identity()
    {
        using var identity = AgeKeygen.Generate();
        var str = identity.ToString();
        Assert.StartsWith("AGE-SECRET-KEY-1", str);
    }
}
