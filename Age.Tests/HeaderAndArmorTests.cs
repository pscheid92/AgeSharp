using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Reading a header without a key, synchronously or not, and armor on its own: converting a
/// file to armor and back, under the same rules decryption applies.
/// </summary>
public class HeaderAndArmorTests
{
    private static readonly byte[] Plaintext = Enumerable.Range(0, 70_000).Select(i => (byte)i).ToArray();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AHeaderReads_TheSameEitherWay(bool armor)
    {
        using var alice = X25519Identity.Generate();
        using var bob = MlKem768X25519Identity.Generate();
        using var carol = MlKem768X25519Identity.Generate();
        var file = new Recipients(bob.Recipient, carol.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = armor });

        var read = AgeHeader.Read(new MemoryStream(file));
        var readAsync = await AgeHeader.ReadAsync(new AsyncOnlyStream(new MemoryStream(file)));

        foreach (var header in new[] { read, readAsync })
        {
            Assert.Equal(armor, header.IsArmored);
            Assert.Equal(2, header.Stanzas.Count);
            Assert.All(header.Stanzas, s => Assert.Equal("mlkem768x25519", s.Type));
        }

        Assert.Equal(read.PayloadOffset, readAsync.PayloadOffset);
    }

    // For an armored file the offset would count decoded bytes, which are no position in the
    // file as stored, so it is not given.
    [Fact]
    public void TheOffset_IsWhereThePayloadStarts_OrNullForArmor()
    {
        using var alice = X25519Identity.Generate();
        var binary = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var armored = new Recipients(alice.Recipient).Encrypt(Plaintext, new AgeEncryptOptions { Armor = true });

        var offset = AgeHeader.Read(new MemoryStream(binary)).PayloadOffset;

        Assert.NotNull(offset);
        Assert.Equal("\n"u8.ToArray(), binary.AsSpan((int)offset!.Value - 1, 1).ToArray());
        Assert.Null(AgeHeader.Read(new MemoryStream(armored)).PayloadOffset);
    }

    // Counted from where reading began, so a file after other data gives the same offset.
    [Fact]
    public void TheOffset_CountsFromWhereReadingBegan()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var stream = new MemoryStream([.. "prefix"u8, .. file]) { Position = 6 };

        Assert.Equal(AgeHeader.Read(new MemoryStream(file)).PayloadOffset, AgeHeader.Read(stream).PayloadOffset);
    }

    [Fact]
    public async Task TheLimits_ApplyToReadingAHeader()
    {
        using var alice = X25519Identity.Generate();
        using var bob = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient, bob.Recipient).Encrypt(Plaintext);
        var options = new AgeDecryptOptions { MaxRecipientStanzas = 1 };

        Assert.Throws<AgeFormatException>(() => AgeHeader.Read(new MemoryStream(file), options));
        await Assert.ThrowsAsync<AgeFormatException>(async () => await AgeHeader.ReadAsync(new MemoryStream(file), options));
    }

    [Fact]
    public async Task RequiringArmor_AppliesToReadingAHeader()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var options = new AgeDecryptOptions { RequireArmor = true };

        Assert.Throws<AgeFormatException>(() => AgeHeader.Read(new MemoryStream(file), options));
        await Assert.ThrowsAsync<AgeFormatException>(async () => await AgeHeader.ReadAsync(new MemoryStream(file), options));
    }

    [Fact]
    public async Task AMalformedHeader_IsAHeaderError_EitherWay()
    {
        var file = "age-encryption.org/v1\n-> X25519\n"u8.ToArray();

        Assert.Throws<AgeFormatException>(() => AgeHeader.Read(new MemoryStream(file)));
        await Assert.ThrowsAsync<AgeFormatException>(async () => await AgeHeader.ReadAsync(new MemoryStream(file)));
    }

    [Fact]
    public async Task Armor_RoundTrips_AndIsTheArmorEncryptionWrites()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        var armored = new MemoryStream();
        Armor.Encode(new MemoryStream(file), armored);

        var armoredAsync = new MemoryStream();
        await Armor.EncodeAsync(new AsyncOnlyStream(new MemoryStream(file)), new AsyncOnlyStream(armoredAsync));
        Assert.Equal(armored.ToArray(), armoredAsync.ToArray());

        Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----\n", Encoding.ASCII.GetString(armored.ToArray()));
        Assert.Equal(Plaintext, new Identities(alice).Decrypt(armored.ToArray()));

        var binary = new MemoryStream();
        Armor.Decode(new MemoryStream(armored.ToArray()), binary);
        Assert.Equal(file, binary.ToArray());

        var binaryAsync = new MemoryStream();
        await Armor.DecodeAsync(new AsyncOnlyStream(new MemoryStream(armored.ToArray())), new AsyncOnlyStream(binaryAsync));
        Assert.Equal(file, binaryAsync.ToArray());
    }

    [Fact]
    public void ArmoringNothing_GivesTheMarkersAlone()
    {
        var armored = new MemoryStream();
        Armor.Encode(new MemoryStream(), armored);

        Assert.Equal("-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n", Encoding.ASCII.GetString(armored.ToArray()));
    }

    [Fact]
    public async Task DecodingWhatIsNotArmor_IsRefused()
    {
        using var alice = X25519Identity.Generate();
        var binary = new Recipients(alice.Recipient).Encrypt(Plaintext);

        Assert.Throws<AgeFormatException>(() => Armor.Decode(new MemoryStream(binary), new MemoryStream()));
        await Assert.ThrowsAsync<AgeFormatException>(() => Armor.DecodeAsync(new MemoryStream(binary), new MemoryStream()));
    }

    [Fact]
    public async Task DecodingHonoursTheArmorLineBound()
    {
        var armored = new MemoryStream();
        Armor.Encode(new MemoryStream(Plaintext), armored);
        var options = new AgeDecryptOptions { MaxArmorLineBytes = 40 };

        Assert.Throws<AgeFormatException>(() => Armor.Decode(new MemoryStream(armored.ToArray()), new MemoryStream(), options));
        await Assert.ThrowsAsync<AgeFormatException>(() => Armor.DecodeAsync(new MemoryStream(armored.ToArray()), new MemoryStream(), options));
    }

    [Fact]
    public async Task TheStreams_AreLeftOpen()
    {
        var input = new MemoryStream(Plaintext);
        var output = new MemoryStream();

        Armor.Encode(input, output);
        await Armor.EncodeAsync(new MemoryStream(Plaintext), output);

        Assert.True(input.CanRead);
        Assert.True(output.CanWrite);
    }
}
