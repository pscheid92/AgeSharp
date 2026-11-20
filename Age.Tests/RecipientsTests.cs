using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A set of recipients encrypts to all of them. Building the set refuses what can never encrypt;
/// encrypting reads and writes the caller's streams asynchronously when asked to.
/// </summary>
public class RecipientsTests
{
    private static readonly byte[] Plaintext = Enumerable.Range(0, 200_000).Select(i => (byte)(i * 7)).ToArray();

    [Fact]
    public void EveryMember_CanDecrypt()
    {
        using var alice = X25519Identity.Generate();
        using var bob = MlKem768X25519Identity.Generate();
        using var carol = X25519Identity.Generate();

        var file = new Recipients(alice.Recipient, carol.Recipient).Encrypt(Plaintext);

        Assert.Equal(Plaintext, Decrypt(file, alice));
        Assert.Equal(Plaintext, Decrypt(file, carol));
        Assert.Throws<NoIdentityMatchException>(() => Decrypt(file, bob));
    }

    [Fact]
    public void ASetIsFixedOnceBuilt()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        IRecipient[] members = [alice.Recipient];

        var set = new Recipients(members);
        members[0] = bob.Recipient;

        Assert.Equal(alice.Recipient.ToString(), Assert.Single(set).ToString());
    }

    [Fact]
    public void ASetBuiltFromAnEnumerable_KeepsTheOrder()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();

        var set = new Recipients(new List<IRecipient> { alice.Recipient, bob.Recipient });

        Assert.Equal(2, set.Count);
        Assert.Equal(alice.Recipient.ToString(), set[0].ToString());
        Assert.Equal(bob.Recipient.ToString(), set[1].ToString());
    }

    [Fact]
    public void AnEmptySet_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => new Recipients());
        Assert.Throws<ArgumentException>(() => new Recipients(new List<IRecipient>()));
        Assert.Throws<ArgumentNullException>(() => new Recipients((IEnumerable<IRecipient>)null!));
    }

    [Fact]
    public void ASet_EnumeratesAsAPlainEnumerableToo()
    {
        using var alice = X25519Identity.Generate();

        var members = new List<object>();
        foreach (var member in (System.Collections.IEnumerable)new Recipients(alice.Recipient))
            members.Add(member);

        Assert.IsType<X25519Recipient>(Assert.Single(members));
    }

    [Fact]
    public void ANullMember_IsRefused()
    {
        using var alice = X25519Identity.Generate();

        Assert.Throws<ArgumentException>(() => new Recipients(alice.Recipient, null!));
    }

    // Refused when the set is built, before any recipient wraps anything.
    [Fact]
    public void APassphraseWithOthers_IsRefusedWhenBuilt()
    {
        var watched = new WatchedRecipient();

        var ex = Assert.Throws<AgeException>(() => new Recipients(watched, new ScryptRecipient("pass", 10)));

        Assert.Contains("only recipient", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, watched.Wraps);
    }

    // A custom recipient can write a scrypt stanza of its own; that is caught once it has.
    [Fact]
    public void AScryptStanzaWithOthers_IsRefusedAfterWrapping()
    {
        var ex = Assert.Throws<AgeException>(() =>
            new Recipients(new WatchedRecipient(), new WatchedRecipient("scrypt")).Encrypt(Plaintext));

        Assert.Contains("only recipient", ex.Message, StringComparison.Ordinal);
    }

    // Null labels are no labels, so such a recipient mixes with any unlabelled one.
    [Fact]
    public void NullLabels_CountAsNone()
    {
        var file = new Recipients(new WatchedRecipient(), new NullLabelsRecipient()).Encrypt(Plaintext);

        Assert.NotEmpty(file);
    }

    [Fact]
    public void APassphraseAlone_Encrypts()
    {
        using var passphrase = new ScryptRecipient("correct horse", 10);

        var file = new Recipients(passphrase).Encrypt(Plaintext);

        Assert.Equal(Plaintext, Decrypt(file, passphrase));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheArmorOption_ChoosesTheEncoding(bool armor)
    {
        using var identity = X25519Identity.Generate();

        var file = new Recipients(identity.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = armor });

        Assert.Equal(armor, file.AsSpan().StartsWith("-----BEGIN AGE ENCRYPTED FILE-----"u8));
        Assert.Equal(Plaintext, Decrypt(file, identity));
    }

    [Fact]
    public void TheStreams_AreLeftOpen()
    {
        using var identity = X25519Identity.Generate();
        using var plaintext = new MemoryStream(Plaintext);
        using var ciphertext = new MemoryStream();

        new Recipients(identity.Recipient).Encrypt(plaintext, ciphertext);

        Assert.True(plaintext.CanRead);
        Assert.True(ciphertext.CanWrite);
    }

    // The bytes form clears the copy it makes on the way in; nothing else of the caller's is touched.
    [Fact]
    public void EncryptingBytes_LeavesTheCallersBytesAlone()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Plaintext.ToArray();

        new Recipients(identity.Recipient).Encrypt(plaintext);

        Assert.Equal(Plaintext, plaintext);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EncryptAsync_NeverReadsOrWritesSynchronously(bool armor)
    {
        using var identity = X25519Identity.Generate();
        var output = new MemoryStream();

        await new Recipients(identity.Recipient).EncryptAsync(
            new AsyncOnlyStream(new MemoryStream(Plaintext)), new AsyncOnlyStream(output),
            new AgeEncryptOptions { Armor = armor });

        Assert.Equal(Plaintext, Decrypt(output.ToArray(), identity));
    }

    [Fact]
    public async Task TheReader_ReadsAsynchronouslyToo()
    {
        using var identity = X25519Identity.Generate();
        var output = new MemoryStream();

        await using (var reader = new Recipients(identity.Recipient).EncryptReader(new AsyncOnlyStream(new MemoryStream(Plaintext))))
            await reader.CopyToAsync(output);

        Assert.Equal(Plaintext, Decrypt(output.ToArray(), identity));
    }

    // The array forms of ReadAsync, which CopyToAsync does not use.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheReader_ReadsIntoArraysAsynchronously(bool armor)
    {
        using var identity = X25519Identity.Generate();
        var output = new MemoryStream();
        var buffer = new byte[10_000];

        await using (var reader = new Recipients(identity.Recipient).EncryptReader(
                         new AsyncOnlyStream(new MemoryStream(Plaintext)), new AgeEncryptOptions { Armor = armor }))
        {
            int read;
            while ((read = await reader.ReadAsync(buffer, 0, buffer.Length, CancellationToken.None)) > 0)
                output.Write(buffer, 0, read);
        }

        Assert.Equal(Plaintext, Decrypt(output.ToArray(), identity));
    }

    [Fact]
    public async Task EncryptDetachedAsync_NeverReadsOrWritesSynchronously()
    {
        using var identity = X25519Identity.Generate();
        var header = new MemoryStream();
        var payload = new MemoryStream();

        await new Recipients(identity.Recipient).EncryptDetachedAsync(
            new AsyncOnlyStream(new MemoryStream(Plaintext)), new AsyncOnlyStream(header), new AsyncOnlyStream(payload));

        using var output = new MemoryStream();
        new Identities(identity).DecryptDetached(new MemoryStream(header.ToArray()), new MemoryStream(payload.ToArray()), output);
        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public async Task EncryptAsync_StopsWhenCancelled()
    {
        using var identity = X25519Identity.Generate();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new Recipients(identity.Recipient).EncryptAsync(new MemoryStream(Plaintext), new MemoryStream(),
                cancellationToken: new CancellationToken(canceled: true)));
    }

    [Fact]
    public void ParsingAFile_ReadsEveryRecipient()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        const string ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJQGjgPbMDwrhAEaWNKLdSIHAxiKJDtMCmLj7Zeg844 test@host";

        var set = Recipients.Parse($"# team\r\n{x25519.Recipient}\r\n\n{pq.Recipient}\n# ssh\n{ssh}");

        Assert.Collection(set,
            r => Assert.IsType<X25519Recipient>(r),
            r => Assert.IsType<MlKem768X25519Recipient>(r),
            r => Assert.IsType<SshEd25519Recipient>(r));
    }

    // As in go-age: a recipients file without a recipient can only ever fail to encrypt.
    [Theory]
    [InlineData("")]
    [InlineData("# nobody\n\n")]
    public void AFileWithoutRecipients_IsRefused(string text)
    {
        var ex = Assert.Throws<FormatException>(() => Recipients.Parse(text));

        Assert.Contains("no recipients", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ABadLine_IsNamed()
    {
        using var identity = X25519Identity.Generate();

        var ex = Assert.Throws<FormatException>(() => Recipients.Parse($"# ok\n{identity.Recipient}\nnot-a-recipient\n"));

        Assert.Contains("line 3", ex.Message, StringComparison.Ordinal);
        Assert.Contains("unrecognized recipient", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseOne_ReadsEveryType()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();

        Assert.IsType<X25519Recipient>(Recipients.ParseOne(x25519.Recipient.ToString()));
        Assert.IsType<MlKem768X25519Recipient>(Recipients.ParseOne(pq.Recipient.ToString()));
        Assert.IsType<SshEd25519Recipient>(Recipients.ParseOne(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJQGjgPbMDwrhAEaWNKLdSIHAxiKJDtMCmLj7Zeg844"));
        Assert.IsType<PluginRecipient>(Recipients.ParseOne(AgeSharp.Crypto.Bech32.Encode("age1example", [1, 2, 3])));
    }

    [Theory]
    [InlineData("")]
    [InlineData("AGE-SECRET-KEY-1QQQ")]
    [InlineData("ssh-dss AAAAB3NzaC1kc3MAAAAA")]
    public void ParseOne_RefusesWhatIsNotARecipient(string text)
    {
        Assert.Throws<FormatException>(() => Recipients.ParseOne(text));
    }

    private static byte[] Decrypt(byte[] file, IIdentity identity)
    {
        using var output = new MemoryStream();
        new Identities(identity).Decrypt(new MemoryStream(file), output);
        return output.ToArray();
    }

    // Counts wraps, to show a refusal came before any.
    private sealed class WatchedRecipient(string stanzaType = "watched") : IRecipient
    {
        public int Wraps { get; private set; }

        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
        {
            Wraps++;
            return [new Stanza(stanzaType, [], fileKey.ToArray())];
        }
    }

    private sealed class NullLabelsRecipient : IRecipientWithLabels
    {
        public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey) => WrapWithLabels(fileKey).Stanzas;

        public LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey) =>
            new([new Stanza("unlabelled", [], fileKey.ToArray())], null!);
    }
}
