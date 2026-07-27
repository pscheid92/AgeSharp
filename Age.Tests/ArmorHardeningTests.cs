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

    // Honest note: this passes with and without the explicit CR guard, because the fragments a
    // bare CR creates already fail the line-width rules. The guard makes the rejection explicit
    // and refactor-proof rather than incidental — it does not close a reachable acceptance, and
    // this test documents the behaviour rather than proving the fix.
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

    // CRLF is legitimate and must keep working — StreamReader consumes it as one terminator, so
    // no CR survives into the line.
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
}
