using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Armored round-trips across every residue of the 48-byte armor line, because the
///     bug this class exists to prevent only appeared at two of them.
/// </summary>
/// <remarks>
///     A final chunk of 46 or 47 bytes encodes to a <em>full</em> 64-column line carrying
///     base64 padding. The decoder used to assume any 64-column line decodes to exactly
///     48 bytes, so it rejected those — meaning AgeSharp could not read roughly one in
///     twenty-four of its own armored files, nor the equivalent files from age or rage.
///     Every existing armor test happened to use a size that avoided it.
/// </remarks>
public class ArmorSizeSweepTests
{
    private const int BytesPerArmorLine = 48;

    private static byte[] Pattern(int length)
    {
        var data = new byte[length];
        new Random(length).NextBytes(data);
        return data;
    }

    [Fact]
    public void EveryResidueOfTheArmorLine_RoundTrips()
    {
        // The ciphertext length, not the plaintext length, is what the armor encoder
        // chunks — so this sweeps plaintext sizes wide enough to cover every residue
        // the ciphertext can land on.
        using var identity = X25519Identity.Generate();
        var failures = new List<string>();

        for (var size = 0; size < BytesPerArmorLine * 3; size++)
        {
            var plaintext = Pattern(size);

            try
            {
                var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
                var back = Age.Decrypt(armored, identity);

                if (!back.SequenceEqual(plaintext))
                    failures.Add($"{size}: content mismatch");
            }
            catch (Exception ex)
            {
                failures.Add($"{size}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        Assert.Empty(failures);
    }

    [Theory]
    // Sizes chosen so the *ciphertext* ends 46 or 47 bytes into an armor line, which
    // is what produces a full-width padded final line.
    [InlineData(65536 * 3 + 999)]
    [InlineData(65536 + 47)]
    [InlineData(65536 + 46)]
    [InlineData(100_000)]
    [InlineData(199_999)]
    public void MultiChunkSizes_RoundTrip(int size)
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(size);

        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        Assert.Equal(plaintext, Age.Decrypt(armored, identity));
    }

    [Fact]
    public void EveryCiphertextResidue_IsExercised()
    {
        // Guards the sweep itself: if the range above ever stopped covering all 48
        // residues, the regression could return unnoticed.
        using var identity = X25519Identity.Generate();
        var residues = new HashSet<int>();

        for (var size = 0; size < BytesPerArmorLine * 3; size++)
            residues.Add(Age.Encrypt(Pattern(size), identity.Recipient).Length % BytesPerArmorLine);

        Assert.Equal(BytesPerArmorLine, residues.Count);
    }

    [Fact]
    public async Task AsyncPath_HandlesTheFullWidthPaddedLine()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Pattern(65536 * 3 + 999);
        var armored = Age.Encrypt(plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new MemoryStream(armored);
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity]);

        Assert.Equal(plaintext, output.ToArray());
    }
}