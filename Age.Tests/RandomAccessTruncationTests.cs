using Age;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// The seekable path must reject a truncated or tampered payload exactly as the
/// forward-only path does. Chunk layout alone cannot tell a truncated file from a
/// shorter one, so <see cref="AgeRandomAccess"/> authenticates the final chunk at
/// construction. Every case here asserts both paths agree.
/// </summary>
public class RandomAccessTruncationTests
{
    // Sizes chosen so the surviving final chunk is exactly its 16-byte tag (cut == size % 65536),
    // which is the case the old layout arithmetic accepted silently.
    [Theory]
    [InlineData(65537, 1)]
    [InlineData(65541, 5)]
    [InlineData(131073, 1)]
    [InlineData(131172, 100)]
    // Truncations that leave a partial final chunk.
    [InlineData(196608, 5)]
    [InlineData(100_000, 1000)]
    [InlineData(200, 7)]
    public void TruncatedPayload_RejectedByBothPaths(int size, int cut)
    {
        using var identity = X25519Identity.Generate();
        var truncated = Truncate(Encrypt(size, identity.Recipient), cut);

        AssertBothPathsReject(truncated, identity);
    }

    // S3: with the whole payload chopped to a single 16-byte tag the computed plaintext
    // length is 0, and nothing at all used to be authenticated.
    [Theory]
    [InlineData(65537)]
    [InlineData(131072)]
    [InlineData(100)]
    public void PayloadChoppedToBareTag_RejectedByBothPaths(int size)
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(size, identity.Recipient);
        var payloadStart = ciphertext.Length - EncryptedLength(size);

        AssertBothPathsReject(ciphertext[..(int)(payloadStart + 16)], identity);
    }

    // S3: an empty file's only chunk is its tag, so a tampered tag or nonce used to be invisible.
    [Theory]
    [InlineData(1)]  // last tag byte
    [InlineData(17)] // last payload-nonce byte
    public void TamperedEmptyFile_RejectedByBothPaths(int bytesFromEnd)
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(0, identity.Recipient);
        ciphertext[^bytesFromEnd] ^= 0xFF;

        AssertBothPathsReject(ciphertext, identity);
    }

    [Fact]
    public void ValidEmptyFile_StillAccepted()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream(Encrypt(0, identity.Recipient));
        using var ra = new AgeRandomAccess(input, identity);

        Assert.Equal(0, ra.PlaintextLength);
        Assert.Equal(0, ra.ReadAt(0, new byte[10]));
    }

    // C11: the spec requires that seeking relative to the end first verify the final chunk.
    // Length and Seek(0, End) are now derived from an authenticated chunk, because a
    // truncated file never yields a reader at all.
    [Fact]
    public void SeekFromEnd_OnTruncatedFile_NeverReportsAWrongLength()
    {
        using var identity = X25519Identity.Generate();
        var truncated = Truncate(Encrypt(196608, identity.Recipient), 5);

        using var input = new MemoryStream(truncated);
        Assert.Throws<AgePayloadException>(() => new AgeRandomAccess(input, identity));
    }

    [Fact]
    public void SeekFromEnd_OnValidFile_ReportsAuthenticatedLength()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[196608];
        new Random(7).NextBytes(plaintext);

        using var input = new MemoryStream(Encrypt(plaintext, identity.Recipient));
        using var ra = new AgeRandomAccess(input, identity);
        using var stream = ra.GetStream();

        Assert.Equal(plaintext.Length, stream.Length);
        Assert.Equal(plaintext.Length, stream.Seek(0, SeekOrigin.End));
    }

    [Fact]
    public void TamperedFinalChunk_RejectedByBothPaths()
    {
        using var identity = X25519Identity.Generate();
        var ciphertext = Encrypt(100_000, identity.Recipient);
        ciphertext[^1] ^= 0xFF;

        AssertBothPathsReject(ciphertext, identity);
    }

    [Fact]
    public void TruncatedArmoredPayload_Rejected()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[65537];
        new Random(9).NextBytes(plaintext);

        using var source = new MemoryStream(plaintext);
        using var armored = new MemoryStream();
        AgeEncrypt.Encrypt(source, armored, armor: true, identity.Recipient);

        // Drop the last body line before the END marker: the dearmored payload loses its
        // final chunk, which layout arithmetic alone would still accept.
        var lines = new List<string>(System.Text.Encoding.ASCII.GetString(armored.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries));
        lines.RemoveAt(lines.Count - 2);
        var bytes = System.Text.Encoding.ASCII.GetBytes(string.Join('\n', lines) + "\n");

        using var input = new MemoryStream(bytes);
        Assert.Throws<AgePayloadException>(() => new AgeRandomAccess(input, identity));
    }

    private static void AssertBothPathsReject(byte[] ciphertext, IIdentity identity)
    {
        using var forwardInput = new MemoryStream(ciphertext);
        using var sink = new MemoryStream();
        Assert.Throws<AgePayloadException>(() => AgeEncrypt.Decrypt(forwardInput, sink, identity));

        using var seekInput = new MemoryStream(ciphertext);
        Assert.Throws<AgePayloadException>(() => new AgeRandomAccess(seekInput, identity));
    }

    private static long EncryptedLength(long plaintextLength)
    {
        var chunks = Math.Max(1, (plaintextLength + 65535) / 65536);
        return plaintextLength + chunks * 16;
    }

    private static byte[] Truncate(byte[] ciphertext, int cut) => ciphertext[..^cut];

    private static byte[] Encrypt(int size, IRecipient recipient)
    {
        var plaintext = new byte[size];
        if (size > 0) new Random(42).NextBytes(plaintext);

        return Encrypt(plaintext, recipient);
    }

    private static byte[] Encrypt(byte[] plaintext, IRecipient recipient)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, recipient);

        return output.ToArray();
    }
}
