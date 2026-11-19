using System.Linq;
using OuterLoop;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Cross-implementation interop tests against the reference <c>age</c> CLI, driven through the
/// <see cref="AgeCli"/> helper so each case is a data row rather than repeated process plumbing.
/// Every test skips cleanly when age is not on PATH. The size rows deliberately straddle the
/// 64 KiB STREAM chunk boundary — where a chunk-nonce or final-flag bug would surface — and the
/// encrypt direction (AgeSharp → age) covers ground the decrypt-only CCTV vectors do not.
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

        var identity = AgeUnderTest.GenerateX25519();
        var plaintext = MakePlaintext(size);

        var ciphertext = AgeUnderTest.Encrypt(plaintext, armored, identity.Recipient);
        var result = AgeCli.Decrypt(identity.Identity, ciphertext);

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

        var identity = AgeUnderTest.GenerateX25519();
        var plaintext = MakePlaintext(size);

        var ciphertext = AgeCli.Encrypt(plaintext, armored, identity.Recipient);
        var result = AgeUnderTest.Decrypt(ciphertext, identity.Identity);

        Assert.Equal(plaintext, result);
    }

    // --- Multiple X25519 recipients: multi-stanza header, every identity must unwrap ---

    [SkippableFact]
    public void MultipleRecipients_EncryptWithCSharp_EachIdentityDecryptsWithAge()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var a = AgeUnderTest.GenerateX25519();
        var b = AgeUnderTest.GenerateX25519();
        var c = AgeUnderTest.GenerateX25519();
        var plaintext = MakePlaintext(4096);

        var ciphertext = AgeUnderTest.Encrypt(plaintext, armored: false, a.Recipient, b.Recipient, c.Recipient);

        foreach (var identity in new[] { a, b, c })
            Assert.Equal(plaintext, AgeCli.Decrypt(identity.Identity, ciphertext));
    }

    [SkippableFact]
    public void MultipleRecipients_EncryptWithAge_EachIdentityDecryptsWithCSharp()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var a = AgeUnderTest.GenerateX25519();
        var b = AgeUnderTest.GenerateX25519();
        var c = AgeUnderTest.GenerateX25519();
        var plaintext = MakePlaintext(4096);

        var ciphertext = AgeCli.Encrypt(plaintext, armored: false,
            a.Recipient, b.Recipient, c.Recipient);

        Assert.Equal(plaintext, AgeUnderTest.Decrypt(ciphertext, a.Identity));
        Assert.Equal(plaintext, AgeUnderTest.Decrypt(ciphertext, b.Identity));
        Assert.Equal(plaintext, AgeUnderTest.Decrypt(ciphertext, c.Identity));
    }

    // --- Shared security policy: mixing post-quantum and classic recipients is refused ---

    [SkippableFact]
    public void MixedPqAndClassicRecipients_RejectedByBothImplementations()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var x25519 = AgeUnderTest.GenerateX25519();
        var pq = AgeUnderTest.GeneratePostQuantum();
        var plaintext = MakePlaintext(64);

        // A file encrypted to both a classic and a post-quantum recipient is only as strong as
        // the classic stanza, defeating the point of the PQ recipient. AgeSharp and the reference
        // age CLI both refuse the combination — this locks in that the two agree on that policy.
        Assert.Throws<AgeUnderTest.Refused>(() =>
            AgeUnderTest.Encrypt(plaintext, armored: false, x25519.Recipient, pq.Recipient));
        Assert.Throws<InvalidOperationException>(() =>
            AgeCli.Encrypt(plaintext, armored: false, x25519.Recipient, pq.Recipient));
    }

    // --- ML-KEM-768-X25519: both directions, binary + armored ---

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void MlKem_EncryptWithCSharp_DecryptWithAge(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var identity = AgeUnderTest.GeneratePostQuantum();
        var plaintext = MakePlaintext(131072);

        var ciphertext = AgeUnderTest.Encrypt(plaintext, armored, identity.Recipient);
        var result = AgeCli.Decrypt(identity.Identity, ciphertext);

        Assert.Equal(plaintext, result);
    }

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void MlKem_EncryptWithAge_DecryptWithCSharp(bool armored)
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var identity = AgeUnderTest.GeneratePostQuantum();
        var plaintext = MakePlaintext(131072);

        var ciphertext = AgeCli.Encrypt(plaintext, armored, identity.Recipient);
        var result = AgeUnderTest.Decrypt(ciphertext, identity.Identity);

        Assert.Equal(plaintext, result);
    }

    // --- Detached header: header + payload recombined must be a standard age file ---

    [SkippableFact]
    public void DetachedHeader_SplitByCSharp_RecombinedDecryptsWithAge()
    {
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var identity = AgeUnderTest.GenerateX25519();
        var plaintext = MakePlaintext(4096);

        var (header, payload) = AgeUnderTest.EncryptDetached(plaintext, identity.Recipient);

        // The detached streams are a standard age file split at the payload boundary;
        // concatenating them must yield bytes age accepts unchanged.
        var recombined = header.Concat(payload).ToArray();
        var result = AgeCli.Decrypt(identity.Identity, recombined);

        Assert.Equal(plaintext, result);
    }

    // --- Armor: every plaintext length through more than four mod-48 cycles ---

    [SkippableFact]
    public void Armored_EncryptWithAge_DecryptWithCSharp_AcrossEveryLengthResidue()
    {
        // The armored body is base64 in 64-character lines, so the shape of the final line
        // cycles with the ciphertext length mod 48. Two residues out of every 48 produce a
        // full-width final line that carries padding — a 46- or 47-byte final chunk — and the
        // decoder used to reject exactly those. Walking 0..220 covers the cycle four times over
        // and pins the two residues that failed (plaintext sizes 38, 39, 86, 87, 134, 135,
        // 182, 183 for a single X25519 recipient).
        Skip.IfNot(AgeCli.Available, "age CLI not found on PATH");

        var identity = AgeUnderTest.GenerateX25519();
        var recipient = identity.Recipient;
        var failures = new List<int>();

        for (var size = 0; size <= 220; size++)
        {
            var plaintext = MakePlaintext(size);
            var ciphertext = AgeCli.Encrypt(plaintext, armored: true, recipient);

            var decryption = AgeUnderTest.TryDecrypt(ciphertext, [identity.Identity]);

            if (decryption.Outcome != AgeUnderTest.Outcome.Success || !decryption.Plaintext!.SequenceEqual(plaintext))
                failures.Add(size);
        }

        Assert.Empty(failures);
    }
}
