using Age;
using Age.Crypto;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class XWingTests
{
    [Fact]
    public void GeneratePublicKey_Deterministic()
    {
        var seed = new byte[32];
        new Random(42).NextBytes(seed);

        var pk1 = XWing.GeneratePublicKey(seed);
        var pk2 = XWing.GeneratePublicKey(seed);

        Assert.Equal(pk1, pk2);
    }

    [Fact]
    public void GeneratePublicKey_CorrectSize()
    {
        var seed = new byte[32];
        new Random(42).NextBytes(seed);

        var pk = XWing.GeneratePublicKey(seed);
        Assert.Equal(XWing.PublicKeySize, pk.Length);  // 1216
    }

    [Fact]
    public void Encaps_Decaps_RoundTrip()
    {
        var seed = new byte[32];
        new Random(42).NextBytes(seed);

        var pk = XWing.GeneratePublicKey(seed);
        var (ss, enc) = XWing.Encaps(pk);

        Assert.Equal(32, ss.Length);
        Assert.Equal(XWing.EncSize, enc.Length);  // 1120

        var ss2 = XWing.Decaps(enc, seed);
        Assert.Equal(ss, ss2);
    }

    [Fact]
    public void Encaps_DifferentSharedSecrets()
    {
        var seed = new byte[32];
        new Random(42).NextBytes(seed);

        var pk = XWing.GeneratePublicKey(seed);
        var (ss1, _) = XWing.Encaps(pk);
        var (ss2, _) = XWing.Encaps(pk);

        // Each encapsulation should produce a different shared secret
        Assert.NotEqual(ss1, ss2);
    }

    [Fact]
    public void Decaps_WrongSeed_DifferentSharedSecret()
    {
        var seed1 = new byte[32];
        new Random(42).NextBytes(seed1);
        var seed2 = new byte[32];
        new Random(99).NextBytes(seed2);

        var pk = XWing.GeneratePublicKey(seed1);
        var (ss, enc) = XWing.Encaps(pk);

        // Decaps with wrong seed should produce different shared secret (implicit rejection)
        var ss2 = XWing.Decaps(enc, seed2);
        Assert.NotEqual(ss, ss2);
    }
}

public class MlKem768X25519RecipientTests
{
    [Fact]
    public void Parse_ToString_RoundTrip()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        var parsed = MlKem768X25519Recipient.Parse(recipientStr);
        Assert.Equal(recipientStr, parsed.ToString());
    }

    [Fact]
    public void Parse_RejectsUppercase()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString().ToUpperInvariant();

        Assert.Throws<FormatException>(() => MlKem768X25519Recipient.Parse(recipientStr));
    }

    [Fact]
    public void Parse_RejectsWrongHrp()
    {
        Assert.Throws<FormatException>(() => MlKem768X25519Recipient.Parse("age1qyqsqzzpj08m"));
    }

    [Fact]
    public void ToString_IsLowercase()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        Assert.Equal(recipientStr, recipientStr.ToLowerInvariant());
        Assert.StartsWith("age1pq1", recipientStr);
    }
}

public class MlKem768X25519ConstructorTests
{
    [Fact]
    public void Constructor_Rejects_WrongKeySize()
    {
        Assert.Throws<ArgumentException>(() => new MlKem768X25519Recipient(new byte[100]));
    }

    [Fact]
    public void Parse_Rejects_WrongDataLength()
    {
        var encoded = Bech32.Encode("age1pq", new byte[100]);
        var ex = Assert.Throws<FormatException>(() => MlKem768X25519Recipient.Parse(encoded));
        Assert.Contains("must be", ex.Message);
    }
}

public class MlKem768X25519IdentityTests
{
    [Fact]
    public void Parse_ToString_RoundTrip()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var identityStr = identity.ToString();

        using var parsed = MlKem768X25519Identity.Parse(identityStr);
        Assert.Equal(identityStr, parsed.ToString());
    }

    [Fact]
    public void Parse_RejectsLowercase()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var identityStr = identity.ToString().ToLowerInvariant();

        Assert.Throws<FormatException>(() => MlKem768X25519Identity.Parse(identityStr));
    }

    [Fact]
    public void Parse_RejectsWrongHrp()
    {
        // Try parsing an X25519 identity as PQ
        using var x25519 = X25519Identity.Generate();
        Assert.Throws<FormatException>(() => MlKem768X25519Identity.Parse(x25519.ToString()));
    }

    [Fact]
    public void ToString_IsUppercase()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var identityStr = identity.ToString();

        Assert.Equal(identityStr, identityStr.ToUpperInvariant());
        Assert.StartsWith("AGE-SECRET-KEY-PQ-1", identityStr);
    }

    [Fact]
    public void Wrap_Unwrap_RoundTrip()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;

        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        var stanza = recipient.Wrap(fileKey);
        Assert.Equal("mlkem768x25519", stanza.Type);
        Assert.Single(stanza.Args);
        Assert.Equal(32, stanza.Body.Length); // 16 key + 16 tag

        var unwrapped = identity.Unwrap(stanza);
        Assert.NotNull(unwrapped);
        Assert.Equal(fileKey, unwrapped);
    }

    [Fact]
    public void Unwrap_WrongIdentity_ReturnsNull()
    {
        using var id1 = MlKem768X25519Identity.Generate();
        using var id2 = MlKem768X25519Identity.Generate();

        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        var stanza = id1.Recipient.Wrap(fileKey);
        var unwrapped = id2.Unwrap(stanza);
        Assert.Null(unwrapped);
    }

    [Fact]
    public void Unwrap_X25519Stanza_ReturnsNull()
    {
        using var pqIdentity = MlKem768X25519Identity.Generate();
        using var x25519Identity = X25519Identity.Generate();

        var fileKey = new byte[16];
        new Random(42).NextBytes(fileKey);

        var x25519Stanza = x25519Identity.Recipient.Wrap(fileKey);
        var unwrapped = pqIdentity.Unwrap(x25519Stanza);
        Assert.Null(unwrapped);
    }

    [Fact]
    public void Recipient_Property_Consistent()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var r1 = identity.Recipient.ToString();
        var r2 = identity.Recipient.ToString();
        Assert.Equal(r1, r2);
    }

    [Fact]
    public void Label_ReturnsPostquantum()
    {
        using var identity = MlKem768X25519Identity.Generate();
        Assert.Equal("postquantum", identity.Recipient.Label);
    }
}

public class PqRoundTripTests
{
    [Fact]
    public void RoundTrip_PQ()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = "Hello, post-quantum age!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void RoundTrip_PQ_Empty()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = Array.Empty<byte>();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void RoundTrip_PQ_Large()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;

        // Test with data larger than one chunk (> 64 KiB)
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void RoundTrip_PQ_MultipleRecipients()
    {
        using var id1 = MlKem768X25519Identity.Generate();
        using var id2 = MlKem768X25519Identity.Generate();

        var plaintext = "multi-recipient PQ test"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, id1.Recipient, id2.Recipient);

        // Decrypt with first identity
        encOutput.Position = 0;
        using var decOutput1 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput1, id1);
        Assert.Equal(plaintext, decOutput1.ToArray());

        // Decrypt with second identity
        encOutput.Position = 0;
        using var decOutput2 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput2, id2);
        Assert.Equal(plaintext, decOutput2.ToArray());
    }

    [Fact]
    public void RoundTrip_PQ_Armored()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;

        var plaintext = "armored PQ test"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, armor: true, recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);

        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void RoundTrip_PQ_KeyRoundTrip()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var identityStr = identity.ToString();
        var recipientStr = identity.Recipient.ToString();

        using var parsed = AgeKeygen.ParsePqIdentity(identityStr);
        var parsedRecipient = AgeKeygen.ParsePqRecipient(recipientStr);

        Assert.Equal(identityStr, parsed.ToString());
        Assert.Equal(recipientStr, parsedRecipient.ToString());
    }

    [Fact]
    public void MixingPrevention_PQ_And_X25519_Throws()
    {
        using var pqId = MlKem768X25519Identity.Generate();
        using var x25519Id = X25519Identity.Generate();

        var plaintext = "test"u8.ToArray();
        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();

        var ex = Assert.Throws<AgeException>(() =>
            AgeEncrypt.Encrypt(encInput, encOutput, pqId.Recipient, x25519Id.Recipient));
        Assert.Contains("different security labels", ex.Message);
    }

    [Fact]
    public void MixingPrevention_X25519_And_PQ_Throws()
    {
        using var pqId = MlKem768X25519Identity.Generate();
        using var x25519Id = X25519Identity.Generate();

        var plaintext = "test"u8.ToArray();
        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();

        var ex = Assert.Throws<AgeException>(() =>
            AgeEncrypt.Encrypt(encInput, encOutput, x25519Id.Recipient, pqId.Recipient));
        Assert.Contains("different security labels", ex.Message);
    }

    [Fact]
    public void Interop_PQ_EncryptWithCSharp_DecryptWithAgeCli()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return; // Skip if age CLI not available

        using var identity = MlKem768X25519Identity.Generate();
        var recipient = identity.Recipient;
        var plaintext = "Hello from C# AgeSharp PQ!"u8.ToArray();

        // Encrypt with C#
        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipient);

        var ciphertext = encOutput.ToArray();
        var tempCipher = Path.GetTempFileName();
        var tempKey = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempCipher, ciphertext);
            File.WriteAllText(tempKey, identity.ToString());

            var psi = new System.Diagnostics.ProcessStartInfo("/opt/homebrew/bin/age", $"-d -i {tempKey} {tempCipher}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            Assert.Equal(0, proc.ExitCode);
            Assert.Equal("Hello from C# AgeSharp PQ!", output);
        }
        finally
        {
            File.Delete(tempCipher);
            File.Delete(tempKey);
        }
    }

    [Fact]
    public void Interop_PQ_EncryptWithAgeCli_DecryptWithCSharp()
    {
        if (!File.Exists("/opt/homebrew/bin/age"))
            return; // Skip if age CLI not available

        using var identity = MlKem768X25519Identity.Generate();
        var recipientStr = identity.Recipient.ToString();

        var tempCipher = Path.GetTempFileName();
        try
        {
            // Encrypt with age CLI
            var psi = new System.Diagnostics.ProcessStartInfo("/opt/homebrew/bin/age", $"-r {recipientStr} -o {tempCipher}")
            {
                RedirectStandardInput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            proc.StandardInput.Write("Hello from age CLI PQ!");
            proc.StandardInput.Close();
            proc.WaitForExit();
            Assert.Equal(0, proc.ExitCode);

            // Decrypt with C#
            var ciphertext = File.ReadAllBytes(tempCipher);
            using var decInput = new MemoryStream(ciphertext);
            using var decOutput = new MemoryStream();
            AgeEncrypt.Decrypt(decInput, decOutput, identity);

            var result = System.Text.Encoding.UTF8.GetString(decOutput.ToArray());
            Assert.Equal("Hello from age CLI PQ!", result);
        }
        finally
        {
            File.Delete(tempCipher);
        }
    }
}
