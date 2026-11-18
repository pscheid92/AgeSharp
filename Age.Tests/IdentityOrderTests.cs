using Age.Format;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The library's own identities are tried before any other, whatever order the caller gives,
/// as in go-age (age.go, decryptHdr). An SSH key or a plugin may ask the user something, a
/// passphrase or a touch; one that is not needed should not.
/// </summary>
public class IdentityOrderTests
{
    private static readonly byte[] Plaintext = "tried in order"u8.ToArray();

    public static TheoryData<string> DecryptionPaths => ["Decrypt", "DecryptReader", "DecryptDetached", "AgeRandomAccess"];

    // go-age's TestDecryptNativeIdentitiesFirst, on every way in.
    [Theory]
    [MemberData(nameof(DecryptionPaths))]
    public void NativeIdentitiesAreTriedFirst(string path)
    {
        using var correct = X25519Identity.Generate();
        using var unrelated = X25519Identity.Generate();
        var other = new Probe("other");

        Assert.Equal(Plaintext, Decrypt(path, Encrypt(correct.Recipient), unrelated, other, correct));
        Assert.Empty(other.Calls);
    }

    [Fact]
    public void OtherIdentitiesKeepTheirOrder()
    {
        using var unrelated = X25519Identity.Generate();
        using var intended = X25519Identity.Generate();
        var calls = new List<string>();
        var first = new Probe("first", calls);
        var second = new Probe("second", calls);

        Assert.Throws<NoIdentityMatchException>(() =>
            Decrypt("Decrypt", Encrypt(intended.Recipient), first, unrelated, second));

        Assert.Equal(["first", "second"], calls);
    }

    // go-age's TestDecryptDoesNotReorderIdentities: the order is the library's to choose, not
    // the caller's array to rearrange.
    [Fact]
    public void TheCallersIdentitiesAreLeftAsTheyWere()
    {
        using var correct = X25519Identity.Generate();
        var other = new Probe("other");
        IIdentity[] identities = [other, correct];

        Decrypt("Decrypt", Encrypt(correct.Recipient), identities);

        Assert.Equal<IIdentity>([other, correct], identities);
    }

    [Fact]
    public void APassphraseProtectedSshKeyListedFirst_IsNotAskedFor_WhenAnotherKeyMatches()
    {
        using var x25519 = X25519Identity.Generate();
        var plainSsh = (SshEd25519Identity)AgeKeygen.ParseSshIdentity(Fixture("ed25519_plain"));
        var ciphertext = Encrypt(plainSsh.Recipient, x25519.Recipient);
        using var protectedSsh = (EncryptedSshIdentity)AgeKeygen.ParseSshIdentity(Fixture("ed25519_aes256ctr"),
            () => throw new InvalidOperationException("the passphrase was asked for"));

        Assert.Equal(Plaintext, Decrypt("Decrypt", ciphertext, protectedSsh, x25519));
    }

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestData", "EncryptedSsh", name));

    private static byte[] Encrypt(params IRecipient[] recipients)
    {
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(new MemoryStream(Plaintext), output, recipients);
        return output.ToArray();
    }

    private static byte[] Decrypt(string path, byte[] ciphertext, params IIdentity[] identities)
    {
        switch (path)
        {
            case "Decrypt":
            {
                using var output = new MemoryStream();
                AgeEncrypt.Decrypt(new MemoryStream(ciphertext), output, identities);
                return output.ToArray();
            }
            case "DecryptReader":
            {
                using var reader = AgeEncrypt.DecryptReader(new MemoryStream(ciphertext), identities);
                using var output = new MemoryStream();
                reader.CopyTo(output);
                return output.ToArray();
            }
            case "DecryptDetached":
            {
                using var header = new MemoryStream();
                using var payload = new MemoryStream();
                // Split the file the way EncryptDetached would have: the header ends at the MAC line.
                var offset = AgeHeader.Parse(new MemoryStream(ciphertext)).PayloadOffset;
                header.Write(ciphertext, 0, (int)offset);
                payload.Write(ciphertext, (int)offset, ciphertext.Length - (int)offset);
                header.Position = payload.Position = 0;
                using var output = new MemoryStream();
                AgeEncrypt.DecryptDetached(header, payload, output, identities);
                return output.ToArray();
            }
            case "AgeRandomAccess":
            {
                using var randomAccess = new AgeRandomAccess(new MemoryStream(ciphertext), identities);
                var plaintext = new byte[randomAccess.PlaintextLength];
                randomAccess.ReadAt(0, plaintext);
                return plaintext;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(path));
        }
    }

    /// <summary>An identity that matches nothing, and records that it was asked.</summary>
    private sealed class Probe(string name, List<string>? log = null) : IIdentity
    {
        public List<string> Calls { get; } = log ?? [];

        public byte[]? Unwrap(Stanza stanza)
        {
            if (Calls.LastOrDefault() != name)
                Calls.Add(name);

            return null;
        }
    }
}
