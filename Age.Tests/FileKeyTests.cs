using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A file's header can be taken out and its file key unwrapped in one place, and the payload
/// decrypted with that key in another, as go-age's ExtractHeader, DecryptHeader and
/// NewInjectedFileKeyIdentity allow. The header's MAC still decides whether a key is the file's.
/// </summary>
public class FileKeyTests
{
    private static readonly byte[] Plaintext = Enumerable.Range(0, 70_000).Select(i => (byte)(i * 3)).ToArray();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AFileKeyUnwrappedFromTheHeader_DecryptsTheFile(bool armor)
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = armor });

        var header = AgeHeader.Read(new MemoryStream(file));
        byte[] carried;
        using (var fileKey = new Identities(alice).UnwrapFileKey(header))
            carried = fileKey.Bytes.ToArray();

        using var key = FileKey.From(carried);
        using var known = new FileKeyIdentity(key);

        Assert.Equal(Plaintext, new Identities(known).Decrypt(file));
    }

    // The header taken out of a whole file is the detached header EncryptDetached writes.
    [Fact]
    public void TheHeaderTakenOut_IsTheDetachedHeader()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var header = AgeHeader.Read(new MemoryStream(file));

        var bytes = header.ToBytes();

        Assert.Equal(file[..(int)header.PayloadOffset!.Value], bytes);
        Assert.Equal(header.Stanzas.Count, AgeHeader.Read(new MemoryStream(bytes)).Stanzas.Count);

        var output = new MemoryStream();
        new Identities(alice).DecryptDetached(new MemoryStream(bytes), new MemoryStream(file[bytes.Length..]), output);
        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void TheHeaderBytes_AreACopy()
    {
        using var alice = X25519Identity.Generate();
        var header = AgeHeader.Read(new MemoryStream(new Recipients(alice.Recipient).Encrypt(Plaintext)));

        var first = header.ToBytes();
        Array.Clear(first);

        Assert.NotEqual(first, header.ToBytes());
    }

    // Whether a key is the file's, the MAC decides: a wrong one is refused, not used.
    [Fact]
    public void AKeyThatIsNotTheFiles_FailsAuthentication()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        using var wrong = FileKey.From(new byte[FileKey.Size]);
        using var known = new FileKeyIdentity(wrong);

        Assert.Throws<AgeAuthenticationException>(() => new Identities(known).Decrypt(file));
    }

    [Fact]
    public void AHeaderNoIdentityOpens_IsANoMatch()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        var header = AgeHeader.Read(new MemoryStream(new Recipients(alice.Recipient).Encrypt(Plaintext)));

        Assert.Throws<NoIdentityMatchException>(() => new Identities(bob).UnwrapFileKey(header));
    }

    [Fact]
    public void AHeaderAlteredAfterEncryption_FailsAuthentication()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var mac = System.Text.Encoding.ASCII.GetString(file).IndexOf("\n--- ", StringComparison.Ordinal) + 5;
        file[mac] = (byte)(file[mac] == 'A' ? 'B' : 'A');

        Assert.Throws<AgeAuthenticationException>(() => new Identities(alice).UnwrapFileKey(AgeHeader.Read(new MemoryStream(file))));
    }

    [Fact]
    public void AFileKeyIs16Bytes()
    {
        Assert.Equal(16, FileKey.Size);
        Assert.Throws<ArgumentException>(() => FileKey.From(new byte[15]));
        Assert.Throws<ArgumentException>(() => FileKey.From(new byte[17]));
    }

    [Fact]
    public void AFileKey_IsCopiedInAndClearedOnDispose()
    {
        var bytes = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var key = FileKey.From(bytes);
        Array.Clear(bytes);

        Assert.Equal(Enumerable.Range(1, 16).Select(i => (byte)i), key.Bytes.ToArray());

        key.Dispose();
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.Bytes.Length);
    }

    [Fact]
    public void TheIdentity_KeepsItsOwnCopy_AndClearsIt()
    {
        var key = FileKey.From(new byte[16]);
        var identity = new FileKeyIdentity(key);
        key.Dispose();

        var buffer = new byte[16];
        Assert.True(identity.TryUnwrap(new Stanza("any", [], []), buffer));

        identity.Dispose();
        Assert.Throws<ObjectDisposedException>(() => identity.TryUnwrap(new Stanza("any", [], []), buffer));
    }

    [Fact]
    public void TheIdentity_RefusesWhatCannotBeAKey()
    {
        using var disposed = FileKey.From(new byte[16]);
        disposed.Dispose();
        using var key = FileKey.From(new byte[16]);
        using var identity = new FileKeyIdentity(key);

        Assert.Throws<ArgumentNullException>(() => new FileKeyIdentity(null!));
        Assert.Throws<ObjectDisposedException>(() => new FileKeyIdentity(disposed));
        Assert.Throws<ArgumentException>(() => identity.TryUnwrap(new Stanza("any", [], []), new byte[15]));
    }

    [Fact]
    public void ADisposedSet_UnwrapsNoKey()
    {
        using var alice = X25519Identity.Generate();
        var header = AgeHeader.Read(new MemoryStream(new Recipients(alice.Recipient).Encrypt(Plaintext)));
        var set = Identities.Parse(alice.ToSecretString());
        set.Dispose();

        Assert.Throws<ObjectDisposedException>(() => set.UnwrapFileKey(header));
        Assert.Throws<ArgumentNullException>(() => new Identities(alice).UnwrapFileKey(null!));
    }

    // The key a header gives is the one the payload was sealed under: the same key decrypts a
    // file read any way, the seekable reader included.
    [Fact]
    public void TheKnownKey_ReadsTheFileEveryWay()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        using var fileKey = new Identities(alice).UnwrapFileKey(AgeHeader.Read(new MemoryStream(file)));
        using var known = new FileKeyIdentity(fileKey);
        var with = new Identities(known);

        using var reader = with.DecryptReader(new MemoryStream(file));
        reader.Position = StreamEncryption.ChunkSize + 7;
        var buffer = new byte[100];
        reader.ReadExactly(buffer);

        Assert.Equal(Plaintext.AsSpan(StreamEncryption.ChunkSize + 7, 100).ToArray(), buffer);
    }
}
