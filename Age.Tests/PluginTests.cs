using Age;
using Age.Crypto;
using Age.Format;
using Age.Plugin;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class PluginTests
{
    // Helper to create a valid Bech32 plugin recipient string
    private static string MakePluginRecipient(string name)
        => Bech32.Encode($"age1{name}", new byte[] { 0x01, 0x02, 0x03 });

    // Helper to create a valid Bech32 plugin identity string (encode lowercase, then uppercase the whole thing)
    private static string MakePluginIdentity(string name)
        => Bech32.Encode($"age-plugin-{name.ToLowerInvariant()}-", new byte[] { 0x01, 0x02, 0x03 }).ToUpperInvariant();

    private sealed class TestCallbacks : IPluginCallbacks
    {
        public List<string> Messages { get; } = new();
        public List<(string Prompt, bool Secret)> SecretRequests { get; } = new();
        public string? SecretResponse { get; set; }
        public List<(string Message, string Yes, string? No)> Confirmations { get; } = new();
        public bool ConfirmResponse { get; set; } = true;

        public void DisplayMessage(string message) => Messages.Add(message);

        public string RequestValue(string prompt, bool secret)
        {
            SecretRequests.Add((prompt, secret));
            return SecretResponse ?? "";
        }

        public bool Confirm(string message, string yes, string? no)
        {
            Confirmations.Add((message, yes, no));
            return ConfirmResponse;
        }
    }

    // --- Plugin name extraction ---

    [Fact]
    public void PluginRecipient_ExtractPluginName_Valid()
    {
        var recipient = MakePluginRecipient("yubikey");
        Assert.Equal("yubikey", PluginRecipient.ExtractPluginName(recipient));
    }

    [Fact]
    public void PluginRecipient_ExtractPluginName_DifferentNames()
    {
        Assert.Equal("tpm", PluginRecipient.ExtractPluginName(MakePluginRecipient("tpm")));
        Assert.Equal("fido2hmac", PluginRecipient.ExtractPluginName(MakePluginRecipient("fido2hmac")));
    }

    [Fact]
    public void PluginIdentity_ExtractPluginName_Valid()
    {
        var identity = MakePluginIdentity("yubikey");
        Assert.Equal("yubikey", PluginIdentity.ExtractPluginName(identity));
    }

    [Fact]
    public void PluginIdentity_ExtractPluginName_DifferentNames()
    {
        Assert.Equal("tpm", PluginIdentity.ExtractPluginName(MakePluginIdentity("tpm")));
        Assert.Equal("fido2hmac", PluginIdentity.ExtractPluginName(MakePluginIdentity("fido2hmac")));
    }

    [Fact]
    public void PluginRecipient_Constructor_StoresPluginName()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("yubikey"));
        Assert.Equal("yubikey", recipient.PluginName);
    }

    [Fact]
    public void PluginIdentity_Constructor_StoresPluginName()
    {
        var identity = new PluginIdentity(MakePluginIdentity("yubikey"));
        Assert.Equal("yubikey", identity.PluginName);
    }

    [Fact]
    public void PluginRecipient_Label_IsNull()
    {
        var recipient = new PluginRecipient(MakePluginRecipient("yubikey"));
        Assert.Null(recipient.Label);
    }

    [Fact]
    public void PluginRecipient_ToString_ReturnsOriginalString()
    {
        var str = MakePluginRecipient("yubikey");
        var recipient = new PluginRecipient(str);
        Assert.Equal(str, recipient.ToString());
    }

    [Fact]
    public void PluginIdentity_ToString_ReturnsOriginalString()
    {
        var str = MakePluginIdentity("yubikey");
        var identity = new PluginIdentity(str);
        Assert.Equal(str, identity.ToString());
    }

    // --- PluginConnection stanza I/O roundtrip ---

    [Fact]
    public void PluginConnection_WriteAndRead_EmptyBody()
    {
        var buffer = new StringWriter();
        var conn = new PluginConnection(new StringReader(""), buffer);
        conn.WriteStanza("test-type", ["arg1", "arg2"], []);

        var output = buffer.ToString();
        Assert.Contains("-> test-type arg1 arg2\n", output);
        // Empty body should have empty line
        Assert.EndsWith("\n\n", output);

        // Now read it back
        var reader = new StringReader(output);
        var readConn = new PluginConnection(reader, new StringWriter());
        var result = readConn.ReadStanza();
        Assert.NotNull(result);
        Assert.Equal("test-type", result.Value.Type);
        Assert.Equal(["arg1", "arg2"], result.Value.Args);
        Assert.Empty(result.Value.Body);
    }

    [Fact]
    public void PluginConnection_WriteAndRead_WithBody()
    {
        var body = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var buffer = new StringWriter();
        var conn = new PluginConnection(new StringReader(""), buffer);
        conn.WriteStanza("data", [], body);

        var output = buffer.ToString();
        var reader = new StringReader(output);
        var readConn = new PluginConnection(reader, new StringWriter());
        var result = readConn.ReadStanza();
        Assert.NotNull(result);
        Assert.Equal("data", result.Value.Type);
        Assert.Empty(result.Value.Args);
        Assert.Equal(body, result.Value.Body);
    }

    [Fact]
    public void PluginConnection_WriteAndRead_LargeBody()
    {
        // Body that encodes to more than 64 chars (>= 49 bytes)
        var body = new byte[64];
        for (int i = 0; i < body.Length; i++) body[i] = (byte)(i & 0xFF);

        var buffer = new StringWriter();
        var conn = new PluginConnection(new StringReader(""), buffer);
        conn.WriteStanza("big", ["x"], body);

        var output = buffer.ToString();
        var reader = new StringReader(output);
        var readConn = new PluginConnection(reader, new StringWriter());
        var result = readConn.ReadStanza();
        Assert.NotNull(result);
        Assert.Equal(body, result.Value.Body);
    }

    [Fact]
    public void PluginConnection_ReadStanza_ReturnsNullAtEof()
    {
        var conn = new PluginConnection(new StringReader(""), new StringWriter());
        Assert.Null(conn.ReadStanza());
    }

    [Fact]
    public void PluginConnection_ReadStanza_ThrowsOnBadPrefix()
    {
        var conn = new PluginConnection(new StringReader("bad line\n"), new StringWriter());
        Assert.Throws<AgePluginException>(() => conn.ReadStanza());
    }

    // --- PluginRecipient.Wrap protocol simulation ---

    [Fact]
    public void PluginRecipient_Wrap_BasicProtocol()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr);
        var fileKey = new byte[16];
        for (int i = 0; i < 16; i++) fileKey[i] = (byte)i;

        // Prepare plugin responses: recipient-stanza, then done
        var wrappedBody = new byte[] { 0xAA, 0xBB, 0xCC };
        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        // Write what the plugin would send back
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519", "ephemeral-key-b64"], wrappedBody);
        mockConn.WriteStanza("done", [], []);

        var pluginResponse = pluginOutput.ToString();

        // Now create connection that reads plugin response and captures our writes
        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);

        var result = recipient.WrapWithConnection(conn, fileKey);

        Assert.Equal("X25519", result.Type);
        Assert.Equal(["ephemeral-key-b64"], result.Args);
        Assert.Equal(wrappedBody, result.Body);

        // Verify Phase 1 output contains expected stanzas
        var sent = capturedOutput.ToString();
        Assert.Contains("-> add-recipient", sent);
        Assert.Contains("-> wrap-file-key", sent);
        Assert.Contains("-> extension-labels", sent);
        Assert.Contains("-> done", sent);
    }

    [Fact]
    public void PluginRecipient_Wrap_ErrorStanza_Throws()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("error", [], System.Text.Encoding.UTF8.GetBytes("something went wrong"));
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("something went wrong", ex.Message);
    }

    [Fact]
    public void PluginRecipient_Wrap_UnknownStanza_RespondsUnsupported()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr);

        var wrappedBody = new byte[] { 0x01 };
        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("grease", ["abc"], new byte[] { 0xFF });
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519"], wrappedBody);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        var result = recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Equal("X25519", result.Type);
        // Should have sent "unsupported" for the grease stanza
        Assert.Contains("-> unsupported", capturedOutput.ToString());
    }

    [Fact]
    public void PluginRecipient_Wrap_MsgStanza_CallsDisplayMessage()
    {
        var recipientStr = MakePluginRecipient("test");
        var callbacks = new TestCallbacks();
        var recipient = new PluginRecipient(recipientStr, callbacks);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("msg", [], System.Text.Encoding.UTF8.GetBytes("Touch your YubiKey"));
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519"], new byte[] { 0x01 });
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Single(callbacks.Messages);
        Assert.Equal("Touch your YubiKey", callbacks.Messages[0]);
    }

    [Fact]
    public void PluginRecipient_Wrap_RequestSecret_CallsCallback()
    {
        var recipientStr = MakePluginRecipient("test");
        var callbacks = new TestCallbacks { SecretResponse = "my-pin-1234" };
        var recipient = new PluginRecipient(recipientStr, callbacks);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("request-secret", [], System.Text.Encoding.UTF8.GetBytes("Enter PIN:"));
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519"], new byte[] { 0x01 });
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Single(callbacks.SecretRequests);
        Assert.Equal("Enter PIN:", callbacks.SecretRequests[0].Prompt);
        Assert.True(callbacks.SecretRequests[0].Secret);
        // Verify ok stanza was sent with the secret value
        Assert.Contains("-> ok", capturedOutput.ToString());
    }

    [Fact]
    public void PluginRecipient_Wrap_RequestSecret_NoCallbacks_Throws()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr); // no callbacks

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("request-secret", [], System.Text.Encoding.UTF8.GetBytes("Enter PIN:"));
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("no callbacks provided", ex.Message);
    }

    [Fact]
    public void PluginRecipient_Wrap_DoneWithoutStanza_Throws()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("without producing a recipient stanza", ex.Message);
    }

    // --- PluginIdentity.Unwrap protocol simulation ---

    [Fact]
    public void PluginIdentity_Unwrap_BasicProtocol()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);
        var fileKey = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("file-key", ["0"], fileKey);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza>
        {
            new("X25519", ["some-arg"], new byte[] { 0xAA, 0xBB })
        };

        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        var result = identity.UnwrapWithConnection(conn, stanzas);

        Assert.NotNull(result);
        Assert.Equal(fileKey, result);

        // Verify Phase 1 output
        var sent = capturedOutput.ToString();
        Assert.Contains("-> add-identity", sent);
        Assert.Contains("-> recipient-stanza 0 X25519 some-arg", sent);
        Assert.Contains("-> done", sent);
    }

    [Fact]
    public void PluginIdentity_Unwrap_MultipleStanzas()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);
        var fileKey = new byte[16];

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("file-key", ["1"], fileKey);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza>
        {
            new("X25519", ["a1"], new byte[] { 0x01 }),
            new("scrypt", ["a2", "18"], new byte[] { 0x02 }),
        };

        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        var result = identity.UnwrapWithConnection(conn, stanzas);

        Assert.NotNull(result);
        var sent = capturedOutput.ToString();
        Assert.Contains("-> recipient-stanza 0 X25519 a1", sent);
        Assert.Contains("-> recipient-stanza 1 scrypt a2 18", sent);
    }

    [Fact]
    public void PluginIdentity_Unwrap_NoMatch_ReturnsNull()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var result = identity.UnwrapWithConnection(conn, stanzas);

        Assert.Null(result);
    }

    [Fact]
    public void PluginIdentity_Unwrap_InternalError_Throws()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("error", ["internal"], System.Text.Encoding.UTF8.GetBytes("plugin crashed"));
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, stanzas));
        Assert.Contains("plugin crashed", ex.Message);
    }

    [Fact]
    public void PluginIdentity_Unwrap_IdentityError_ContinuesToDone()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("error", ["identity"], System.Text.Encoding.UTF8.GetBytes("wrong key"));
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var result = identity.UnwrapWithConnection(conn, stanzas);

        Assert.Null(result);
    }

    [Fact]
    public void PluginIdentity_Unwrap_UnknownStanza_RespondsUnsupported()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);
        var fileKey = new byte[16];

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("grease", [], new byte[] { 0xFF });
        mockConn.WriteStanza("file-key", ["0"], fileKey);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        identity.UnwrapWithConnection(conn, stanzas);

        Assert.Contains("-> unsupported", capturedOutput.ToString());
    }

    [Fact]
    public void PluginIdentity_Unwrap_RequestSecret_CallsCallback()
    {
        var identityStr = MakePluginIdentity("test");
        var callbacks = new TestCallbacks { SecretResponse = "my-pin" };
        var identity = new PluginIdentity(identityStr, callbacks);
        var fileKey = new byte[16];

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("request-secret", [], System.Text.Encoding.UTF8.GetBytes("Enter PIN:"));
        mockConn.WriteStanza("file-key", ["0"], fileKey);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        identity.UnwrapWithConnection(conn, stanzas);

        Assert.Single(callbacks.SecretRequests);
        Assert.Equal("Enter PIN:", callbacks.SecretRequests[0].Prompt);
    }

    // --- Parsing tests ---

    [Fact]
    public void ParseRecipientsFile_PluginRecipient()
    {
        var pluginRecip = MakePluginRecipient("yubikey");
        var text = $"# plugin key\n{pluginRecip}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Single(parsed);
        Assert.IsType<PluginRecipient>(parsed[0]);
        Assert.Equal(pluginRecip, parsed[0].ToString());
    }

    [Fact]
    public void ParseRecipientsFile_MlKem_NotTreatedAsPlugin()
    {
        // ML-KEM recipients start with age1pq and should NOT be treated as plugins
        using var pq = MlKem768X25519Identity.Generate();
        var text = $"{pq.Recipient}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Single(parsed);
        Assert.IsType<MlKem768X25519Recipient>(parsed[0]);
    }

    [Fact]
    public void ParseRecipientsFile_X25519_NotTreatedAsPlugin()
    {
        // Standard age recipients have only one '1' and should NOT be treated as plugins
        using var x25519 = X25519Identity.Generate();
        var text = $"{x25519.Recipient}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Single(parsed);
        Assert.IsType<X25519Recipient>(parsed[0]);
    }

    [Fact]
    public void ParseRecipientsFile_MixedWithPlugin()
    {
        using var x25519 = X25519Identity.Generate();
        var pluginRecip = MakePluginRecipient("yubikey");
        var text = $"{x25519.Recipient}\n{pluginRecip}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Equal(2, parsed.Count);
        Assert.IsType<X25519Recipient>(parsed[0]);
        Assert.IsType<PluginRecipient>(parsed[1]);
    }

    [Fact]
    public void ParseIdentityFile_PluginIdentity()
    {
        var pluginId = MakePluginIdentity("yubikey");
        var text = $"# plugin identity\n{pluginId}\n";

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Single(parsed);
        Assert.IsType<PluginIdentity>(parsed[0]);
        Assert.Equal(pluginId, parsed[0].ToString());
    }

    [Fact]
    public void ParseIdentityFile_MixedWithPlugin()
    {
        using var x25519 = X25519Identity.Generate();
        var pluginId = MakePluginIdentity("yubikey");
        var text = $"{x25519}\n{pluginId}\n";

        var parsed = AgeKeygen.ParseIdentityFile(text);
        Assert.Equal(2, parsed.Count);
        Assert.IsType<X25519Identity>(parsed[0]);
        Assert.IsType<PluginIdentity>(parsed[1]);
    }

    [Fact]
    public void ParseRecipientsFile_WithCallbacks_PassedToPluginRecipient()
    {
        var pluginRecip = MakePluginRecipient("yubikey");
        var callbacks = new TestCallbacks();
        var text = $"{pluginRecip}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text, callbacks);
        Assert.Single(parsed);
        Assert.IsType<PluginRecipient>(parsed[0]);
    }

    [Fact]
    public void ParseIdentityFile_WithCallbacks_PassedToPluginIdentity()
    {
        var pluginId = MakePluginIdentity("yubikey");
        var callbacks = new TestCallbacks();
        var text = $"{pluginId}\n";

        var parsed = AgeKeygen.ParseIdentityFile(text, callbacks);
        Assert.Single(parsed);
        Assert.IsType<PluginIdentity>(parsed[0]);
    }

    // --- Default batch Unwrap on IIdentity ---

    [Fact]
    public void IIdentity_DefaultBatchUnwrap_IteratesCorrectly()
    {
        // Use a real X25519 identity to verify the default batch method works
        using var identity = X25519Identity.Generate();
        var fileKey = new byte[16];
        for (int i = 0; i < 16; i++) fileKey[i] = (byte)i;

        // Create a stanza that matches this identity
        var stanza = identity.Recipient.Wrap(fileKey);

        // Create a non-matching stanza
        using var other = X25519Identity.Generate();
        var otherStanza = other.Recipient.Wrap(fileKey);

        // Batch unwrap with the matching stanza second (cast to IIdentity for default method)
        var stanzas = new List<Stanza> { otherStanza, stanza };
        var result = ((IIdentity)identity).Unwrap(stanzas);
        Assert.NotNull(result);
        Assert.Equal(fileKey, result);
    }

    [Fact]
    public void IIdentity_DefaultBatchUnwrap_NoMatch_ReturnsNull()
    {
        using var identity = X25519Identity.Generate();
        using var other = X25519Identity.Generate();
        var stanza = other.Recipient.Wrap(new byte[16]);

        var result = ((IIdentity)identity).Unwrap(new List<Stanza> { stanza });
        Assert.Null(result);
    }

    // --- AgeEncrypt.Decrypt still works with existing identities ---

    [Fact]
    public void AgeEncrypt_Decrypt_X25519_StillWorks()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "Hello, batch unwrap!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, identity.Recipient);

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, identity);
        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void AgeEncrypt_Decrypt_Scrypt_StillWorks()
    {
        var plaintext = "Hello, scrypt!"u8.ToArray();
        var passphrase = "test-passphrase";

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, new ScryptRecipient(passphrase, 10));

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, new ScryptRecipient(passphrase));
        Assert.Equal(plaintext, decOutput.ToArray());
    }

    // --- Confirm callback ---

    [Fact]
    public void PluginRecipient_Wrap_ConfirmStanza_CallsCallback()
    {
        var recipientStr = MakePluginRecipient("test");
        var callbacks = new TestCallbacks { ConfirmResponse = true };
        var recipient = new PluginRecipient(recipientStr, callbacks);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("confirm", ["yes-btn", "no-btn"], System.Text.Encoding.UTF8.GetBytes("Allow access?"));
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519"], new byte[] { 0x01 });
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Single(callbacks.Confirmations);
        Assert.Equal("Allow access?", callbacks.Confirmations[0].Message);
        Assert.Equal("yes-btn", callbacks.Confirmations[0].Yes);
        Assert.Equal("no-btn", callbacks.Confirmations[0].No);
        Assert.Contains("-> ok", capturedOutput.ToString());
    }

    [Fact]
    public void PluginRecipient_Wrap_ConfirmDenied_SendsFail()
    {
        var recipientStr = MakePluginRecipient("test");
        var callbacks = new TestCallbacks { ConfirmResponse = false };
        var recipient = new PluginRecipient(recipientStr, callbacks);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("confirm", ["yes-btn"], System.Text.Encoding.UTF8.GetBytes("Allow?"));
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519"], new byte[] { 0x01 });
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        recipient.WrapWithConnection(conn, new byte[16]);

        Assert.Contains("-> fail", capturedOutput.ToString());
    }

    [Fact]
    public void PluginRecipient_Wrap_ConfirmNoCallbacks_Throws()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr); // no callbacks

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("confirm", [], System.Text.Encoding.UTF8.GetBytes("Allow?"));
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("no callbacks provided", ex.Message);
    }

    // --- Additional coverage: PluginConnection edge cases ---

    [Fact]
    public void PluginConnection_WriteAndRead_ExactMultipleOf64Body()
    {
        // 48 bytes encodes to exactly 64 base64 chars — tests the extra empty final line branch
        var body = new byte[48];
        for (int i = 0; i < body.Length; i++) body[i] = (byte)i;

        var buffer = new StringWriter();
        var conn = new PluginConnection(new StringReader(""), buffer);
        conn.WriteStanza("exact", [], body);

        var output = buffer.ToString();
        var reader = new StringReader(output);
        var readConn = new PluginConnection(reader, new StringWriter());
        var result = readConn.ReadStanza();
        Assert.NotNull(result);
        Assert.Equal(body, result.Value.Body);
    }

    [Fact]
    public void PluginConnection_ReadStanza_EofDuringBody_Throws()
    {
        // Stanza header with no body lines following
        var conn = new PluginConnection(new StringReader("-> test\n"), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => conn.ReadStanza());
        Assert.Contains("unexpected end of stream", ex.Message);
    }

    [Fact]
    public void PluginConnection_ReadStanza_BodyLineTooLong_Throws()
    {
        // Stanza header followed by a body line > 64 chars
        var longLine = new string('A', 65);
        var conn = new PluginConnection(new StringReader($"-> test\n{longLine}\n"), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => conn.ReadStanza());
        Assert.Contains("exceeds 64 characters", ex.Message);
    }

    [Fact]
    public void PluginConnection_ReadStanza_EmptyType_Throws()
    {
        var conn = new PluginConnection(new StringReader("-> \n\n"), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => conn.ReadStanza());
        Assert.Contains("at least a type", ex.Message);
    }

    [Fact]
    public void PluginConnection_Dispose_WithoutProcess_NoThrow()
    {
        var conn = new PluginConnection(new StringReader(""), new StringWriter());
        conn.Dispose(); // should not throw
    }

    // --- Additional coverage: PluginRecipient edge cases ---

    [Fact]
    public void PluginRecipient_Wrap_RecipientStanzaMissingArgs_Throws()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        // recipient-stanza with only 1 arg (missing type)
        mockConn.WriteStanza("recipient-stanza", ["0"], new byte[] { 0x01 });
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
        Assert.Contains("missing file index or type", ex.Message);
    }

    [Fact]
    public void PluginRecipient_Wrap_UnexpectedEof_Throws()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr);

        // Empty plugin output — EOF immediately
        var conn = new PluginConnection(new StringReader(""), new StringWriter());
        Assert.Throws<AgePluginException>(() => recipient.WrapWithConnection(conn, new byte[16]));
    }

    [Fact]
    public void PluginRecipient_Wrap_MsgWithoutCallbacks_NoThrow()
    {
        var recipientStr = MakePluginRecipient("test");
        var recipient = new PluginRecipient(recipientStr); // no callbacks

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("msg", [], System.Text.Encoding.UTF8.GetBytes("info"));
        mockConn.WriteStanza("recipient-stanza", ["0", "X25519"], new byte[] { 0x01 });
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var result = recipient.WrapWithConnection(conn, new byte[16]);
        Assert.Equal("X25519", result.Type);
    }

    [Fact]
    public void PluginRecipient_ExtractPluginName_InvalidHrp_Throws()
    {
        // Encode with an HRP that doesn't start with "age"
        var badStr = Bech32.Encode("notage1foo", new byte[] { 0x01 });
        Assert.Throws<FormatException>(() => PluginRecipient.ExtractPluginName(badStr));
    }

    // --- Additional coverage: PluginIdentity edge cases ---

    [Fact]
    public void PluginIdentity_Unwrap_MsgWithoutCallbacks_NoThrow()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr); // no callbacks
        var fileKey = new byte[16];

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("msg", [], System.Text.Encoding.UTF8.GetBytes("info"));
        mockConn.WriteStanza("file-key", ["0"], fileKey);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var result = identity.UnwrapWithConnection(conn, stanzas);
        Assert.NotNull(result);
    }

    [Fact]
    public void PluginIdentity_Unwrap_RequestSecretNoCallbacks_Throws()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr); // no callbacks

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("request-secret", [], System.Text.Encoding.UTF8.GetBytes("PIN:"));
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, stanzas));
        Assert.Contains("no callbacks provided", ex.Message);
    }

    [Fact]
    public void PluginIdentity_Unwrap_ConfirmNoCallbacks_Throws()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr); // no callbacks

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("confirm", [], System.Text.Encoding.UTF8.GetBytes("Allow?"));
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, stanzas));
        Assert.Contains("no callbacks provided", ex.Message);
    }

    [Fact]
    public void PluginIdentity_Unwrap_ConfirmCallsCallback()
    {
        var identityStr = MakePluginIdentity("test");
        var callbacks = new TestCallbacks { ConfirmResponse = true };
        var identity = new PluginIdentity(identityStr, callbacks);
        var fileKey = new byte[16];

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("confirm", ["yes-btn", "no-btn"], System.Text.Encoding.UTF8.GetBytes("Allow?"));
        mockConn.WriteStanza("file-key", ["0"], fileKey);
        mockConn.WriteStanza("done", [], []);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var capturedOutput = new StringWriter();
        var conn = new PluginConnection(new StringReader(pluginResponse), capturedOutput);
        var result = identity.UnwrapWithConnection(conn, stanzas);

        Assert.NotNull(result);
        Assert.Single(callbacks.Confirmations);
        Assert.Equal("Allow?", callbacks.Confirmations[0].Message);
        Assert.Contains("-> ok", capturedOutput.ToString());
    }

    [Fact]
    public void PluginIdentity_Unwrap_FileKeyMissingIndex_Throws()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);

        var pluginOutput = new StringWriter();
        var mockConn = new PluginConnection(new StringReader(""), pluginOutput);
        mockConn.WriteStanza("file-key", [], new byte[16]);
        var pluginResponse = pluginOutput.ToString();

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(pluginResponse), new StringWriter());
        var ex = Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, stanzas));
        Assert.Contains("missing file index", ex.Message);
    }

    [Fact]
    public void PluginIdentity_Unwrap_UnexpectedEof_Throws()
    {
        var identityStr = MakePluginIdentity("test");
        var identity = new PluginIdentity(identityStr);

        var stanzas = new List<Stanza> { new("X25519", [], new byte[] { 0x01 }) };
        var conn = new PluginConnection(new StringReader(""), new StringWriter());
        Assert.Throws<AgePluginException>(() => identity.UnwrapWithConnection(conn, stanzas));
    }

    [Fact]
    public void PluginIdentity_ExtractPluginName_InvalidHrp_Throws()
    {
        var badStr = Bech32.Encode("not-a-plugin-", new byte[] { 0x01 });
        Assert.Throws<FormatException>(() => PluginIdentity.ExtractPluginName(badStr));
    }
}
