using System.Linq;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Cross-implementation interop tests against the reference <c>age</c> CLI, driven through the
/// <see cref="AgeCli"/> helper so each case is a data row rather than repeated process plumbing.
/// Every test skips cleanly when age is not on PATH. The size rows deliberately straddle the
/// 64 KiB STREAM chunk boundary — where a chunk-nonce or final-flag bug would surface — and the
/// encrypt direction (age-sharp → age) covers ground the decrypt-only CCTV vectors do not.
/// </summary>
public class InteropTests
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

    // --- X25519: full size × armor matrix, both directions ---

    [SkippableTheory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65535, false)]
    [InlineData(65536, false)]
    [InlineData(65537, false)]
    [InlineData(131072, false)]
    [InlineData(1048576, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65535, true)]
    [InlineData(65536, true)]
    [InlineData(65537, true)]
    [InlineData(131072, true)]
    [InlineData(1048576, true)]
    public void X25519_EncryptWithCSharp_DecryptWithAge(int size, bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = EncryptWithCSharp(plaintext, armored, identity.Recipient);
        var result = AgeCli.Decrypt(identity.ToSecretString(), ciphertext);

        Assert.Equal(plaintext, result);
    }

    [SkippableTheory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(65535, false)]
    [InlineData(65536, false)]
    [InlineData(65537, false)]
    [InlineData(131072, false)]
    [InlineData(1048576, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(65535, true)]
    [InlineData(65536, true)]
    [InlineData(65537, true)]
    [InlineData(131072, true)]
    [InlineData(1048576, true)]
    public void X25519_EncryptWithAge_DecryptWithCSharp(int size, bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(size);

        var ciphertext = AgeCli.Encrypt(plaintext, armored, identity.Recipient.ToString());
        var result = DecryptWithCSharp(ciphertext, identity);

        Assert.Equal(plaintext, result);
    }

    // --- Multiple X25519 recipients: multi-stanza header, every identity must unwrap ---

    [SkippableFact]
    public void MultipleRecipients_EncryptWithCSharp_EachIdentityDecryptsWithAge()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        using var c = X25519Identity.Generate();
        var plaintext = MakePlaintext(4096);

        var ciphertext = EncryptWithCSharp(plaintext, armored: false, a.Recipient, b.Recipient, c.Recipient);

        foreach (var identity in new[] { a, b, c })
            Assert.Equal(plaintext, AgeCli.Decrypt(identity.ToSecretString(), ciphertext));
    }

    [SkippableFact]
    public void MultipleRecipients_EncryptWithAge_EachIdentityDecryptsWithCSharp()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var a = X25519Identity.Generate();
        using var b = X25519Identity.Generate();
        using var c = X25519Identity.Generate();
        var plaintext = MakePlaintext(4096);

        var ciphertext = AgeCli.Encrypt(plaintext, armored: false,
            a.Recipient.ToString(), b.Recipient.ToString(), c.Recipient.ToString());

        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, a));
        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, b));
        Assert.Equal(plaintext, DecryptWithCSharp(ciphertext, c));
    }

    // --- Shared security policy: mixing post-quantum and classic recipients is refused ---

    [SkippableFact]
    public void MixedPqAndClassicRecipients_RejectedByBothImplementations()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var plaintext = MakePlaintext(64);

        // A file encrypted to both a classic and a post-quantum recipient is only as strong as
        // the classic stanza, defeating the point of the PQ recipient. age-sharp and the reference
        // age CLI both refuse the combination — this locks in that the two agree on that policy.
        Assert.Throws<AgeException>(() =>
            EncryptWithCSharp(plaintext, armored: false, x25519.Recipient, pq.Recipient));
        Assert.Throws<InvalidOperationException>(() =>
            AgeCli.Encrypt(plaintext, armored: false, x25519.Recipient.ToString(), pq.Recipient.ToString()));
    }

    // --- ML-KEM-768-X25519: both directions, binary + armored ---

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void MlKem_EncryptWithCSharp_DecryptWithAge(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = MlKem768X25519Identity.Generate();
        var plaintext = MakePlaintext(131072);

        var ciphertext = EncryptWithCSharp(plaintext, armored, identity.Recipient);
        var result = AgeCli.Decrypt(identity.ToSecretString(), ciphertext);

        Assert.Equal(plaintext, result);
    }

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void MlKem_EncryptWithAge_DecryptWithCSharp(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = MlKem768X25519Identity.Generate();
        var plaintext = MakePlaintext(131072);

        var ciphertext = AgeCli.Encrypt(plaintext, armored, identity.Recipient.ToString());
        var result = DecryptWithCSharp(ciphertext, identity);

        Assert.Equal(plaintext, result);
    }

    // --- Detached header: header + payload recombined must be a standard age file ---

    [SkippableFact]
    public void DetachedHeader_SplitByCSharp_RecombinedDecryptsWithAge()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        using var identity = X25519Identity.Generate();
        var plaintext = MakePlaintext(4096);

        using var input = new MemoryStream(plaintext);
        using var header = new MemoryStream();
        using var payload = new MemoryStream();
        AgeEncrypt.EncryptDetached(input, header, payload, identity.Recipient);

        // The detached streams are a standard age file split at the payload boundary;
        // concatenating them must yield bytes age accepts unchanged.
        var recombined = header.ToArray().Concat(payload.ToArray()).ToArray();
        var result = AgeCli.Decrypt(identity.ToSecretString(), recombined);

        Assert.Equal(plaintext, result);
    }
}
