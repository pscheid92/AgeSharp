using System.Text;
using Age.Crypto;
using Age.Recipients;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Age.Tests;

/// <summary>
/// C8 / C9 / C10 — all eight X25519 agreement sites now go through one guarded helper. This is
/// defence in depth plus a consistent exception type, not the closing of an exploitable hole:
/// BouncyCastle already refuses low-order points, so no zero shared secret was ever used. What
/// was broken is the exception contract — five sites let a raw <c>InvalidOperationException</c>
/// escape, so a caller catching <see cref="AgeException"/> to handle hostile files crashed, and
/// the CLI reported a merely malformed input file as "This is a bug".
/// </summary>
public class AgreementGuardTests
{
    // Canonical low-order and identity points for Curve25519.
    public static TheoryData<string, string> LowOrderPoints() => new()
    {
        { "all zeroes (identity)", new string('0', 64) },
        { "u = 1", "0100000000000000000000000000000000000000000000000000000000000000" },
        { "order 8", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800" },
        { "order 4", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157" },
        { "p - 1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
    };

    [Theory]
    [MemberData(nameof(LowOrderPoints))]
    public void X25519Agree_RejectsLowOrderPoints(string name, string pointHex)
    {
        Assert.NotEmpty(name);

        var privateKey = new X25519PrivateKeyParameters(new SecureRandom());
        var point = new X25519PublicKeyParameters(Convert.FromHexString(pointHex));
        var sharedSecret = new byte[CryptoHelper.X25519SharedSecretSize];

        var ex = Assert.Throws<AgeHeaderException>(
            () => CryptoHelper.X25519Agree(privateKey, point, sharedSecret));

        Assert.Contains("all-zero", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void X25519Agree_AcceptsAnHonestPeer()
    {
        var a = new X25519PrivateKeyParameters(new SecureRandom());
        var b = new X25519PrivateKeyParameters(new SecureRandom());

        var ab = new byte[CryptoHelper.X25519SharedSecretSize];
        var ba = new byte[CryptoHelper.X25519SharedSecretSize];

        CryptoHelper.X25519Agree(a, b.GeneratePublicKey(), ab);
        CryptoHelper.X25519Agree(b, a.GeneratePublicKey(), ba);

        Assert.Equal(ab, ba);
        Assert.Contains(ab, x => x != 0);
    }

    // End to end through the public API: a tampered ephemeral share must surface as an
    // AgeException, which is what a caller is documented to catch.
    [Theory]
    [MemberData(nameof(LowOrderPoints))]
    public void TamperedEphemeralShare_IsCatchableAsAgeException(string name, string pointHex)
    {
        Assert.NotEmpty(name);

        using var identity = X25519Identity.Generate();

        using var input = new MemoryStream("guarded"u8.ToArray());
        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(input, encrypted, identity.Recipient);

        var tampered = ReplaceFirstStanzaArg(encrypted.ToArray(), "X25519",
            Base64Unpadded.Encode(Convert.FromHexString(pointHex)));

        var ex = Record.Exception(() =>
        {
            using var source = new MemoryStream(tampered);
            using var output = new MemoryStream();
            AgeEncrypt.Decrypt(source, output, identity);
        });

        Assert.NotNull(ex);
        Assert.IsAssignableFrom<AgeException>(ex);
    }

    // A recipient can carry a low-order point too, so the encrypt side is guarded as well.
    [Theory]
    [MemberData(nameof(LowOrderPoints))]
    public void RecipientCarryingALowOrderPoint_IsCatchableAsAgeException(string name, string pointHex)
    {
        Assert.NotEmpty(name);

        var recipient = X25519Recipient.Parse(Bech32.Encode("age", Convert.FromHexString(pointHex)));

        var ex = Record.Exception(() =>
        {
            using var input = new MemoryStream("guarded"u8.ToArray());
            using var output = new MemoryStream();
            AgeEncrypt.Encrypt(input, output, recipient);
        });

        Assert.NotNull(ex);
        Assert.IsAssignableFrom<AgeException>(ex);
    }

    private static byte[] ReplaceFirstStanzaArg(byte[] file, string stanzaType, string replacement)
    {
        var lines = Encoding.ASCII.GetString(file).Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].StartsWith($"-> {stanzaType} ", StringComparison.Ordinal))
                continue;

            var parts = lines[i].Split(' ');
            parts[2] = replacement;
            lines[i] = string.Join(' ', parts);

            return Encoding.ASCII.GetBytes(string.Join('\n', lines));
        }

        throw new InvalidOperationException($"no {stanzaType} stanza found");
    }
}
