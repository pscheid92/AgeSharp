using System.Text;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// H9 / H11 — armor input hardening, bringing main in line with both reference implementations.
/// </summary>
public class ArmorHardeningTests
{
    private static byte[] Armored(X25519Recipient recipient, byte[] plaintext)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, armor: true, recipient);
        return output.ToArray();
    }

    private static byte[] Decrypt(byte[] file, IIdentity identity)
    {
        using var input = new MemoryStream(file);
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(input, output, identity);
        return output.ToArray();
    }

    // H9. Lines end only at LF (with one trailing CR trimmed), so a bare CR inside a body line
    // stays in the line and fails the base64 character check.
    [Fact]
    public void BareCarriageReturnInArmorBody_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var armored = Encoding.ASCII.GetString(Armored(identity.Recipient, "hello armor"u8.ToArray()));

        // Split one body line with a bare CR rather than a newline.
        var lines = armored.Split('\n');
        var bodyIndex = Array.FindIndex(lines, l => l.Length > 8 && !l.StartsWith("-----", StringComparison.Ordinal));
        lines[bodyIndex] = lines[bodyIndex][..4] + "\r" + lines[bodyIndex][4..];

        var tampered = Encoding.ASCII.GetBytes(string.Join('\n', lines));

        Assert.Throws<AgeArmorException>(() => Decrypt(tampered, identity));
    }

    // Lines end at LF, with one trailing CR allowed — go-age's rule. A lone CR is not a line
    // ending: the same file with every LF replaced by CR used to decrypt, because StreamReader
    // ends lines at a lone CR too.
    [Fact]
    public void LoneCarriageReturnLineEndings_AreRejected()
    {
        using var identity = X25519Identity.Generate();
        var armored = Encoding.ASCII.GetString(Armored(identity.Recipient, "hello armor"u8.ToArray()));

        var crOnly = Encoding.ASCII.GetBytes(armored.Replace('\n', '\r'));

        Assert.Throws<AgeArmorException>(() => Decrypt(crOnly, identity));
    }

    // The per-line memory bound must count lines the way the reader splits them. If it reset at a
    // CR while the reader waited for LF, a CR every few kilobytes would let one line grow unbounded.
    [Fact]
    public void LineBrokenOnlyByCarriageReturns_HitsTheLineLimit()
    {
        var chunk = new string('A', 1000) + "\r";
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n"
                   + string.Concat(Enumerable.Repeat(chunk, AgeLimits.MaxArmorLineBytes / 1000 + 10)) + "\n";

        var ex = Assert.Throws<AgeArmorException>(() => AgeHeader.Parse(new MemoryStream(Encoding.ASCII.GetBytes(text))));

        Assert.Contains($"exceeds {AgeLimits.MaxArmorLineBytes} bytes", ex.Message);
    }

    // CRLF is legitimate and must keep working — the CR before each LF is trimmed, so none
    // survives into the line.
    [Fact]
    public void CrlfLineEndings_StillDecrypt()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "hello armor"u8.ToArray();

        var armored = Encoding.ASCII.GetString(Armored(identity.Recipient, plaintext));
        var crlf = Encoding.ASCII.GetBytes(armored.Replace("\n", "\r\n"));

        Assert.Equal(plaintext, Decrypt(crlf, identity));
    }

    [Fact]
    public void ModestLeadingWhitespace_IsStillAccepted()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "hello armor"u8.ToArray();

        var padded = (byte[]) [.. Encoding.ASCII.GetBytes(new string('\n', 8)), .. Armored(identity.Recipient, plaintext)];

        Assert.Equal(plaintext, Decrypt(padded, identity));
    }

    // Without a bound, a file that is nothing but newlines is read to its end before the header
    // is even looked for.
    [Fact]
    public void UnboundedLeadingWhitespace_IsRejected()
    {
        using var identity = X25519Identity.Generate();

        var flood = (byte[])
        [
            .. Encoding.ASCII.GetBytes(new string('\n', 64 * 1024)),
            .. Armored(identity.Recipient, "hello armor"u8.ToArray()),
        ];

        var ex = Assert.Throws<AgeArmorException>(() => Decrypt(flood, identity));
        Assert.Contains("whitespace", ex.Message, StringComparison.Ordinal);
    }

    // go-age (armor.go) allows 1024 bytes of whitespace-only lines before the header and counts
    // nothing else; the header line used to count against the allowance too, so 990 blank lines
    // were already "more than 1024 bytes of whitespace".
    [Theory]
    [InlineData(1024, true)]
    [InlineData(1025, false)]
    public void LeadingWhitespace_IsAllowedUpToTheLimit(int newlines, bool accepted)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "hello armor"u8.ToArray();
        var padded = (byte[]) [.. Encoding.ASCII.GetBytes(new string('\n', newlines)), .. Armored(identity.Recipient, plaintext)];

        if (accepted)
            Assert.Equal(plaintext, Decrypt(padded, identity));
        else
            Assert.Throws<AgeArmorException>(() => Decrypt(padded, identity));
    }

    // Bounded after the footer as well, as go-age bounds it: otherwise a file followed by
    // nothing but newlines is read to its end before it is accepted.
    [Theory]
    [InlineData(100, true)]
    [InlineData(64 * 1024, false)]
    public void TrailingWhitespace_IsAllowedUpToTheLimit(int newlines, bool accepted)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "hello armor"u8.ToArray();
        var padded = (byte[]) [.. Armored(identity.Recipient, plaintext), .. Encoding.ASCII.GetBytes(new string('\n', newlines))];

        if (accepted)
        {
            Assert.Equal(plaintext, Decrypt(padded, identity));
        }
        else
        {
            var ex = Assert.Throws<AgeArmorException>(() => Decrypt(padded, identity));
            Assert.Contains("whitespace", ex.Message, StringComparison.Ordinal);
        }
    }
}
