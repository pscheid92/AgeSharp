using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     The README's examples, compiled and run. They are the first thing anyone copies,
///     and ten PRs reshaped this API in a single day — several claims went stale without
///     anything failing. A compiler is a better reviewer than a careful reread.
/// </summary>
public class ReadmeExamplesTests
{
    [Fact]
    public void EncryptAndDecrypt()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;

        using var input = new MemoryStream("Hello, age!"u8.ToArray());
        using var encrypted = new MemoryStream();
        Age.Encrypt(input, encrypted, [recipient]);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        Age.Decrypt(encrypted, decrypted, [identity]);

        Assert.Equal("Hello, age!"u8.ToArray(), decrypted.ToArray());

        var ciphertext = Age.Encrypt("secret"u8, [recipient]);
        var plaintext = Age.Decrypt(ciphertext, [identity]);
        Assert.Equal("secret"u8.ToArray(), plaintext);
    }

    [Fact]
    public void PassphraseAndSpanOverload()
    {
        using var passphrase = new Passphrase("correct-horse-battery-staple", 10);

        var ciphertext = Age.Encrypt("hi"u8, [passphrase]);
        Assert.Equal("hi"u8.ToArray(), Age.Decrypt(ciphertext, [passphrase]));

        var typed = "typed-in".ToCharArray();
        using var fromSpan = new Passphrase(typed, 10);
        Array.Clear(typed);
        Assert.NotNull(fromSpan);
    }

    [Fact]
    public void ArmorAndStrictness()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream("hi"u8.ToArray());
        using var encrypted = new MemoryStream();

        Age.Encrypt(input, encrypted, [identity.Recipient], new AgeEncryptOptions { Armor = true });

        using var output = new MemoryStream();
        Age.Decrypt(new MemoryStream(encrypted.ToArray()), output, [identity], new AgeDecryptOptions { RequireArmor = true });

        Assert.Equal("hi"u8.ToArray(), output.ToArray());
    }

    [Fact]
    public void MultipleRecipients_PositionalAndCollection()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();

        using var input = new MemoryStream("hi"u8.ToArray());
        using var encrypted = new MemoryStream();
        Age.Encrypt(input, encrypted, [alice.Recipient, bob.Recipient]);

        using var decrypted = new MemoryStream();
        Age.Decrypt(new MemoryStream(encrypted.ToArray()), decrypted, [bob]);
        Assert.Equal("hi"u8.ToArray(), decrypted.ToArray());

        // The collection form the README shows — no splatting.
        List<IRecipient> recipients = [alice.Recipient, bob.Recipient];
        using var input2 = new MemoryStream("hi"u8.ToArray());
        using var encrypted2 = new MemoryStream();
        Age.Encrypt(input2, encrypted2, recipients);
        Age.Encrypt(new MemoryStream("hi"u8.ToArray()), new MemoryStream(), recipients, new AgeEncryptOptions { Armor = true });

        Assert.NotEqual(0, encrypted2.Length);
    }

    [Fact]
    public void StreamingGrid_AllFourCells()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;
        var plaintext = "streaming"u8.ToArray();

        // encrypt / pull
        using var encryptedStream = Age.EncryptReader(new MemoryStream(plaintext), [recipient]);
        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        // encrypt / push
        using var destination = new MemoryStream();
        using (var stream = Age.EncryptWriter(destination, [recipient]))
        {
            new MemoryStream(plaintext).CopyTo(stream);
        }

        // decrypt / pull
        using var decryptedStream = Age.DecryptReader(new MemoryStream(ciphertext.ToArray()), [identity]);
        using var outputStream = new MemoryStream();
        decryptedStream.CopyTo(outputStream);
        Assert.Equal(plaintext, outputStream.ToArray());

        // decrypt / push
        using var pushOut = new MemoryStream();
        using (var stream = Age.DecryptWriter(pushOut, [identity]))
        {
            new MemoryStream(destination.ToArray()).CopyTo(stream);
        }

        Assert.Equal(plaintext, pushOut.ToArray());
    }

    [Fact]
    public async Task AsyncExamples()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;
        var cancellationToken = CancellationToken.None;

        using var input = new MemoryStream("hi"u8.ToArray());
        using var output = new MemoryStream();
        await Age.EncryptAsync(input, output, [recipient], new AgeEncryptOptions { Armor = true }, cancellationToken);

        using var ciphertext = new MemoryStream(output.ToArray());
        using var plain = new MemoryStream();
        await Age.DecryptAsync(ciphertext, plain, [identity], cancellationToken: cancellationToken);
        Assert.Equal("hi"u8.ToArray(), plain.ToArray());

        using var source = new MemoryStream(output.ToArray());
        await using var stream = await Age.DecryptReaderAsync(source, [identity], cancellationToken: cancellationToken);
        using var outputStream = new MemoryStream();
        await stream.CopyToAsync(outputStream, cancellationToken);
        Assert.Equal("hi"u8.ToArray(), outputStream.ToArray());
    }

    [Fact]
    public void SeekableDecryption()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(3).NextBytes(plaintext);
        var ciphertext = new MemoryStream(Age.Encrypt(plaintext, [identity.Recipient]));

        using var stream = Age.DecryptReader(ciphertext, [identity]);

        Assert.Equal(plaintext.Length, stream.Length);

        var buf = new byte[100];
        stream.Seek(50000, SeekOrigin.Begin);
        stream.ReadExactly(buf);

        Assert.Equal(plaintext.AsSpan(50000, 100).ToArray(), buf);
    }

    [Fact]
    public void HeaderInspection_IsSafeAgainstEmptyArgs()
    {
        // The README example as written must survive a stanza with no arguments,
        // since ReadHeader does not authenticate what it parses.
        using var identity = X25519Identity.Generate();
        var stream = new MemoryStream(Age.Encrypt("hi"u8, [identity.Recipient]));

        var header = Age.ReadHeader(stream);

        Assert.NotEmpty(header.Stanzas);
        Assert.False(header.IsArmored);
        Assert.True(header.PayloadOffset > 0);

        foreach (var stanza in header.Stanzas)
            _ = $"  {stanza.Type}: {string.Join(' ', stanza.Args)}";

        // And explicitly: zero args must not throw the way Args[0] would.
        var empty = new Stanza("custom", [], new byte[1]);
        _ = string.Join(' ', empty.Args);
    }

    [Fact]
    public void ParseExistingKeys()
    {
        using var generated = X25519Identity.Generate();

        var recipient = Age.ParseRecipient(generated.Recipient.ToString());
        var identity = Age.ParseIdentity(generated.ToSecretString());

        Assert.NotNull(recipient);
        Assert.NotNull(identity);
        Assert.True(Age.TryParseRecipient(generated.Recipient.ToString(), out _));
        Assert.False(Age.TryParseRecipient("not-a-recipient", out _));
    }

    [Fact]
    public void DetachedHeaders()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream("hi"u8.ToArray());
        using var headerOutput = new MemoryStream();
        using var payloadOutput = new MemoryStream();

        Age.EncryptDetached(input, headerOutput, payloadOutput, [identity.Recipient]);

        using var headerInput = new MemoryStream(headerOutput.ToArray());
        using var payloadInput = new MemoryStream(payloadOutput.ToArray());
        using var output = new MemoryStream();
        Age.DecryptDetached(headerInput, payloadInput, output, [identity]);

        Assert.Equal("hi"u8.ToArray(), output.ToArray());
    }

    [Fact]
    public void ParsingLimits()
    {
        using var identity = X25519Identity.Generate();
        var options = new AgeDecryptOptions { MaxHeaderBytes = 1024 * 1024 };

        using var input = new MemoryStream(Age.Encrypt("hi"u8, [identity.Recipient]));
        using var output = new MemoryStream();
        Age.Decrypt(input, output, [identity], options);

        Assert.Equal("hi"u8.ToArray(), output.ToArray());
    }

    [Fact]
    public void ErrorHandlingExample()
    {
        using var identity = X25519Identity.Generate();
        using var stranger = X25519Identity.Generate();
        using var input = new MemoryStream(Age.Encrypt("hi"u8, [identity.Recipient]));
        using var output = new MemoryStream();

        try
        {
            Age.Decrypt(input, output, [stranger]);
            Assert.Fail("expected a mismatch");
        }
        catch (NoIdentityMatchException)
        {
        }
        catch (AgeAuthenticationException)
        {
            Assert.Fail("wrong branch");
        }
        catch (AgeFormatException)
        {
            Assert.Fail("wrong branch");
        }
    }
}