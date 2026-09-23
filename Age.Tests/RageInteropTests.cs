using System.Security.Cryptography;
using System.Text;
using Age.Recipients;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Interop with Rust's <c>rage</c>, the second implementation AgeSharp must agree with, in the
/// shape of <see cref="InteropTests"/>. Every test skips cleanly when rage is not on PATH.
/// rage 0.11 has no mlkem768x25519 recipients, so post-quantum interop is Go's alone.
/// </summary>
public class RageInteropTests
{
    private static byte[] MakePlaintext(int size)
    {
        var data = new byte[size];
        for (var i = 0; i < size; i++)
            data[i] = (byte)((i * 31 + 7) & 0xFF);
        return data;
    }

    private static byte[] EncryptWithCSharp(byte[] plaintext, bool armored, params IRecipient[] recipients)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, armored, recipients);
        return output.ToArray();
    }

    private static byte[] DecryptWithCSharp(byte[] ciphertext, params IIdentity[] identities)
    {
        using var input = new MemoryStream(ciphertext);
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(input, output, identities);
        return output.ToArray();
    }

    // --- X25519: sizes straddling the 64 KiB chunk boundary × armor, both directions ---

    [SkippableTheory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65535, false)]
    [InlineData(65536, false)]
    [InlineData(65537, false)]
    [InlineData(1048576, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65535, true)]
    [InlineData(65536, true)]
    [InlineData(65537, true)]
    [InlineData(1048576, true)]
    public void X25519_EncryptWithCSharp_DecryptWithRage(int size, bool armored)
    {
        Skip.IfNot(RageCli.Available, "rage CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = EncryptWithCSharp(plaintext, armored, identity.Recipient);

        Assert.Equal(plaintext, RageCli.Decrypt(identity.ToSecretString() + "\n", ciphertext));
    }

    [SkippableTheory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65535, false)]
    [InlineData(65536, false)]
    [InlineData(65537, false)]
    [InlineData(1048576, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65535, true)]
    [InlineData(65536, true)]
    [InlineData(65537, true)]
    [InlineData(1048576, true)]
    public void X25519_EncryptWithRage_DecryptWithCSharp(int size, bool armored)
    {
        Skip.IfNot(RageCli.Available, "rage CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = RageCli.Encrypt(plaintext, armored, identity.Recipient.ToString());

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, identity));
    }

    // --- Several recipients: every identity must decrypt what the other side produced ---

    [SkippableFact]
    public void MultipleRecipients_EncryptWithCSharp_EachIdentityDecryptsWithRage()
    {
        Skip.IfNot(RageCli.Available, "rage CLI not found on PATH");

        using var first = X25519Identity.Generate();
        using var second = X25519Identity.Generate();
        var plaintext = MakePlaintext(1000);

        var ciphertext = EncryptWithCSharp(plaintext, false, first.Recipient, second.Recipient);

        Assert.Equal(plaintext, RageCli.Decrypt(first.ToSecretString() + "\n", ciphertext));
        Assert.Equal(plaintext, RageCli.Decrypt(second.ToSecretString() + "\n", ciphertext));
    }

    [SkippableFact]
    public void MultipleRecipients_EncryptWithRage_EachIdentityDecryptsWithCSharp()
    {
        Skip.IfNot(RageCli.Available, "rage CLI not found on PATH");

        using var first = X25519Identity.Generate();
        using var second = X25519Identity.Generate();
        var plaintext = MakePlaintext(1000);

        var ciphertext = RageCli.Encrypt(plaintext, false, first.Recipient.ToString(), second.Recipient.ToString());

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, first));
        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, second));
    }

    // --- SSH Ed25519, both directions ---

    [SkippableFact]
    public void SshEd25519_EncryptWithCSharp_DecryptWithRage()
    {
        Skip.IfNot(RageCli.Available, "rage CLI not found on PATH");

        var (authorizedKey, privateKeyPem) = GenerateSshEd25519();
        var plaintext = MakePlaintext(1000);

        var ciphertext = EncryptWithCSharp(plaintext, false, AgeKeygen.ParseSshRecipient(authorizedKey));

        Assert.Equal(plaintext, RageCli.Decrypt(privateKeyPem, ciphertext));
    }

    [SkippableFact]
    public void SshEd25519_EncryptWithRage_DecryptWithCSharp()
    {
        Skip.IfNot(RageCli.Available, "rage CLI not found on PATH");

        var (authorizedKey, privateKeyPem) = GenerateSshEd25519();
        var plaintext = MakePlaintext(1000);

        var ciphertext = RageCli.Encrypt(plaintext, false, authorizedKey);

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, AgeKeygen.ParseSshIdentity(privateKeyPem)));
    }

    private static (string AuthorizedKey, string PrivateKeyPem) GenerateSshEd25519()
    {
        var privateKey = new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32));
        var wire = OpenSshPublicKeyUtilities.EncodePublicKey(privateKey.GeneratePublicKey());
        var blob = Convert.ToBase64String(OpenSshPrivateKeyUtilities.EncodePrivateKey(privateKey));

        var pem = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < blob.Length; i += 70)
            pem.Append(blob.AsSpan(i, Math.Min(70, blob.Length - i))).Append('\n');
        pem.Append("-----END OPENSSH PRIVATE KEY-----\n");

        return ($"ssh-ed25519 {Convert.ToBase64String(wire)} test@example.com", pem.ToString());
    }
}
