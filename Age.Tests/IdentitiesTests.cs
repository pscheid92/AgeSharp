using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A set of identities decrypts what any of them can open. It disposes only what it parsed, reads
/// and writes asynchronously when asked to, and parses headers under the limits it is given.
/// </summary>
public class IdentitiesTests
{
    private static readonly byte[] Plaintext = Enumerable.Range(0, 200_000).Select(i => (byte)(i * 11)).ToArray();

    [Fact]
    public void AnyMember_Decrypts()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        var file = new Recipients(bob.Recipient).Encrypt(Plaintext);

        Assert.Equal(Plaintext, new Identities(alice, bob).Decrypt(file));
    }

    [Fact]
    public void AnEmptySet_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => new Identities());
        Assert.Throws<ArgumentException>(() => new Identities(new List<IIdentity>()));
        Assert.Throws<ArgumentNullException>(() => new Identities((IEnumerable<IIdentity>)null!));
    }

    [Fact]
    public void ANullMember_IsRefused()
    {
        using var alice = X25519Identity.Generate();

        Assert.Throws<ArgumentException>(() => new Identities(alice, null!));
    }

    [Fact]
    public void ASetKeepsTheOrderItWasGiven()
    {
        using var alice = X25519Identity.Generate();
        using var passphrase = new Passphrase("pass", 10);

        var set = new Identities(new List<IIdentity> { alice, passphrase });

        Assert.Equal(2, set.Count);
        Assert.Same(alice, set[0]);
        Assert.Same(passphrase, set[1]);

        var members = new List<object>();
        foreach (var member in (System.Collections.IEnumerable)set)
            members.Add(member);
        Assert.Equal([alice, passphrase], members);
    }

    [Fact]
    public void DisposingTheSet_LeavesTheIdentitiesItWasGiven()
    {
        using var alice = X25519Identity.Generate();

        new Identities(alice).Dispose();

        Assert.StartsWith("AGE-SECRET-KEY-1", alice.ToSecretString());
    }

    [Fact]
    public void DisposingTheSet_ClearsTheIdentitiesItParsed()
    {
        using var alice = X25519Identity.Generate();
        var set = Identities.Parse(alice.ToSecretString());
        var parsed = (X25519Identity)set[0];

        set.Dispose();
        set.Dispose();

        Assert.Throws<ObjectDisposedException>(() => parsed.ToSecretString());
    }

    [Fact]
    public void ADisposedSet_DecryptsNoMore()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var set = Identities.Parse(alice.ToSecretString());
        set.Dispose();

        Assert.Throws<ObjectDisposedException>(() => set.Decrypt(file));
        Assert.Throws<ObjectDisposedException>(() => set.DecryptDetached(new MemoryStream(), new MemoryStream(), new MemoryStream()));
    }

    [Fact]
    public void ParsingAFile_ReadsEveryIdentity()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();

        using var set = Identities.Parse($"# keys\r\n{x25519.ToSecretString()}\r\n\n{pq.ToSecretString()}\n");

        Assert.Collection(set,
            i => Assert.IsType<X25519Identity>(i),
            i => Assert.IsType<MlKem768X25519Identity>(i));
    }

    // The keys before the bad line are disposed on the way out; the caller never sees them.
    [Fact]
    public void ABadLineAfterAKey_RefusesTheWholeFile()
    {
        using var alice = X25519Identity.Generate();

        var ex = Assert.Throws<FormatException>(() => Identities.Parse($"{alice.ToSecretString()}\nnot-a-key\n"));

        Assert.Contains("line 2", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseOne_ReadsEveryType()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();

        using var a = Identities.ParseOne(x25519.ToSecretString());
        using var b = Identities.ParseOne(pq.ToSecretString());
        using var c = Identities.ParseOne(AgeSharp.Crypto.Bech32.Encode("age-plugin-example-", [1, 2, 3]).ToUpperInvariant());
        using var d = Identities.ParseOne(Ed25519Pem());

        Assert.IsType<X25519Identity>(a);
        Assert.IsType<MlKem768X25519Identity>(b);
        Assert.IsType<PluginIdentity>(c);
        Assert.IsType<SshEd25519Identity>(d);
    }

    // Messages end up in logs: a line that almost is a key is not quoted back.
    [Theory]
    [InlineData("")]
    [InlineData("age1notanidentity")]
    [InlineData("AGE-SECRET-KEY-1QQQQQQQ")]
    public void ParseOne_RefusesWhatIsNotAnIdentity(string text)
    {
        var ex = Assert.Throws<FormatException>(() => Identities.ParseOne(text));

        if (text.Length > 0)
            Assert.DoesNotContain(text, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RequiringArmor_RefusesBinary_AndAcceptsArmor()
    {
        using var alice = X25519Identity.Generate();
        var to = new Recipients(alice.Recipient);
        var with = new Identities(alice);
        var options = new AgeDecryptOptions { RequireArmor = true };

        var ex = Assert.Throws<AgeArmorException>(() => with.Decrypt(to.Encrypt(Plaintext), options));
        Assert.Contains("not ASCII-armored", ex.Message, StringComparison.Ordinal);

        Assert.Equal(Plaintext, with.Decrypt(to.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }), options));
    }

    [Fact]
    public async Task RequiringArmor_RefusesBinary_Asynchronously()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        await Assert.ThrowsAsync<AgeArmorException>(() =>
            new Identities(alice).DecryptAsync(new MemoryStream(file), new MemoryStream(), new AgeDecryptOptions { RequireArmor = true }));
    }

    [Fact]
    public async Task RequiringArmor_OnADetachedHeader_IsACallersMistake()
    {
        using var alice = X25519Identity.Generate();
        var with = new Identities(alice);
        var options = new AgeDecryptOptions { RequireArmor = true };

        Assert.Throws<ArgumentException>(() => with.DecryptDetached(new MemoryStream(), new MemoryStream(), new MemoryStream(), options));
        await Assert.ThrowsAsync<ArgumentException>(() => with.DecryptDetachedAsync(new MemoryStream(), new MemoryStream(), new MemoryStream(), options));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ALimitMustBePositive(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxHeaderBytes = value });
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxRecipientStanzas = value });
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxStanzaArguments = value });
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgeDecryptOptions { MaxArmorLineBytes = value });
    }

    [Fact]
    public void TheDefaults_AreGoAges()
    {
        var options = new AgeDecryptOptions();

        Assert.False(options.RequireArmor);
        Assert.Equal(2 * 1024 * 1024, options.MaxHeaderBytes);
        Assert.Equal(1024, options.MaxRecipientStanzas);
        Assert.Equal(128, options.MaxStanzaArguments);
        Assert.Equal(1024, options.MaxArmorLineBytes);
    }

    [Fact]
    public void MaxRecipientStanzas_IsHonoured()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient, bob.Recipient).Encrypt(Plaintext);
        var with = new Identities(alice);

        var ex = Assert.Throws<AgeHeaderException>(() => with.Decrypt(file, new AgeDecryptOptions { MaxRecipientStanzas = 1 }));
        Assert.Contains("more than 1 recipient stanzas", ex.Message, StringComparison.Ordinal);

        Assert.Equal(Plaintext, with.Decrypt(file, new AgeDecryptOptions { MaxRecipientStanzas = 2 }));
    }

    [Fact]
    public void MaxHeaderBytes_IsHonoured()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        var ex = Assert.Throws<AgeHeaderException>(() => new Identities(alice).Decrypt(file, new AgeDecryptOptions { MaxHeaderBytes = 50 }));
        Assert.Contains("header exceeds 50 bytes", ex.Message, StringComparison.Ordinal);
    }

    // Raising a limit lets through what the default refuses: a stanza with more arguments than
    // go-age allows parses, and simply matches no identity.
    [Fact]
    public void MaxStanzaArguments_CanBeRaised()
    {
        using var alice = X25519Identity.Generate();
        var file = WithExtraStanza(new Recipients(alice.Recipient).Encrypt(Plaintext), arguments: 129);
        var with = new Identities(X25519Identity.Generate());

        var ex = Assert.Throws<AgeHeaderException>(() => with.Decrypt(file));
        Assert.Contains("more than 128 arguments", ex.Message, StringComparison.Ordinal);

        Assert.Throws<NoIdentityMatchException>(() => with.Decrypt(file, new AgeDecryptOptions { MaxStanzaArguments = 200 }));
    }

    [Fact]
    public async Task MaxArmorLineBytes_IsHonoured_SyncAndAsync()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = true });
        var with = new Identities(alice);
        var options = new AgeDecryptOptions { MaxArmorLineBytes = 40 };

        Assert.Contains("exceeds 40 bytes", Assert.Throws<AgeArmorException>(() => with.Decrypt(file, options)).Message, StringComparison.Ordinal);

        var async = await Assert.ThrowsAsync<AgeArmorException>(() => with.DecryptAsync(new MemoryStream(file), new MemoryStream(), options));
        Assert.Contains("exceeds 40 bytes", async.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DecryptAsync_NeverReadsOrWritesSynchronously(bool armor)
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = armor });
        var output = new MemoryStream();

        await new Identities(alice).DecryptAsync(new AsyncOnlyStream(new MemoryStream(file)), new AsyncOnlyStream(output));

        Assert.Equal(Plaintext, output.ToArray());
    }

    // The array form of ReadAsync, which CopyToAsync does not use.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheAsyncReader_ReadsIntoArraysAsynchronously(bool armor)
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = armor });
        var output = new MemoryStream();
        var buffer = new byte[10_000];

        await using (var reader = await new Identities(alice).DecryptReaderAsync(new AsyncOnlyStream(new MemoryStream(file))))
        {
            int read;
            while ((read = await reader.ReadAsync(buffer, 0, buffer.Length, CancellationToken.None)) > 0)
                output.Write(buffer, 0, read);
        }

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public async Task DecryptDetachedAsync_NeverReadsOrWritesSynchronously()
    {
        using var alice = X25519Identity.Generate();
        var header = new MemoryStream();
        var payload = new MemoryStream();
        new Recipients(alice.Recipient).EncryptDetached(new MemoryStream(Plaintext), header, payload);
        var output = new MemoryStream();

        await new Identities(alice).DecryptDetachedAsync(
            new AsyncOnlyStream(new MemoryStream(header.ToArray())), new AsyncOnlyStream(new MemoryStream(payload.ToArray())),
            new AsyncOnlyStream(output));

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public async Task NoMatch_IsReportedAsynchronouslyToo()
    {
        using var alice = X25519Identity.Generate();
        using var stranger = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = true });

        await Assert.ThrowsAsync<NoIdentityMatchException>(async () =>
            await new Identities(stranger).DecryptReaderAsync(new AsyncOnlyStream(new MemoryStream(file))));
    }

    [Fact]
    public async Task ATruncatedNonce_IsAHeaderError_SyncAndAsync()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var headerLength = (int)AgeHeader.Read(new MemoryStream(file)).PayloadOffset!.Value;
        var truncated = file[..(headerLength + 5)];
        var with = new Identities(alice);

        Assert.Contains("payload nonce", Assert.Throws<AgeHeaderException>(() => with.Decrypt(truncated)).Message, StringComparison.Ordinal);
        var async = await Assert.ThrowsAsync<AgeHeaderException>(() => with.DecryptAsync(new MemoryStream(truncated), new MemoryStream()));
        Assert.Contains("payload nonce", async.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DecryptAsync_StopsWhenCancelled()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new Identities(alice).DecryptAsync(new MemoryStream(file), new MemoryStream(),
                cancellationToken: new CancellationToken(canceled: true)));
    }

    [Fact]
    public void DecryptingBytes_ReturnsOnlyThePlaintext()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        var plaintext = new Identities(alice).Decrypt(file);

        Assert.Equal(Plaintext.Length, plaintext.Length);
        Assert.Equal(Plaintext, plaintext);
    }

    // Inserts an unknown stanza with the given number of arguments before the MAC line; the MAC
    // no longer matches, but the header is refused or accepted before that is checked.
    private static byte[] WithExtraStanza(byte[] file, int arguments)
    {
        var mac = file.AsSpan().IndexOf("\n---"u8) + 1;
        var stanza = Encoding.ASCII.GetBytes("-> extra " + string.Join(' ', Enumerable.Repeat("a", arguments)) + "\n\n");

        return [.. file[..mac], .. stanza, .. file[mac..]];
    }

    // An unprotected OpenSSH Ed25519 private key.
    private static string Ed25519Pem()
    {
        var key = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(new byte[32]);
        var blob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(key);
        var b64 = Convert.ToBase64String(blob);

        var pem = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < b64.Length; i += 70)
            pem.Append(b64.AsSpan(i, Math.Min(70, b64.Length - i))).Append('\n');

        return pem.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
    }
}
