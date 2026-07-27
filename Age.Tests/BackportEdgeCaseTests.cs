using Age.Crypto;
using Age.Format;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Guards on the backported paths that the ordinary round-trip tests never reach: a custom
/// identity returning the wrong-sized file key, random access over a truncated payload, and the
/// encode overload's own bounds check.
/// </summary>
public class BackportEdgeCaseTests
{
    // A custom or plugin identity is caller-supplied code and can hand back anything. Accepting a
    // wrong-sized key would derive garbage rather than fail, so the guard runs before the header
    // MAC is verified and must clear the key on the way out (S9).
    private sealed class WrongSizedKeyIdentity : IIdentity
    {
        public byte[]? Unwrap(Stanza stanza) => new byte[15];
    }

    [Fact]
    public void IdentityReturningAWrongSizedFileKey_IsRejected()
    {
        using var real = X25519Identity.Generate();

        using var input = new MemoryStream("edge"u8.ToArray());
        using var encrypted = new MemoryStream();
        AgeEncrypt.Encrypt(input, encrypted, real.Recipient);

        using var source = new MemoryStream(encrypted.ToArray());
        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeHeaderException>(
            () => AgeEncrypt.Decrypt(source, output, new WrongSizedKeyIdentity()));

        Assert.Contains("file key must be", ex.Message, StringComparison.Ordinal);
    }

    // --- Random access over damaged payloads: the same rejections the forward-only path makes ---

    private static byte[] Encrypted(X25519Identity identity, int size)
    {
        var plaintext = new byte[size];
        for (var i = 0; i < size; i++) plaintext[i] = (byte)(i * 31 % 251);

        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, identity.Recipient);

        return output.ToArray();
    }

    [Fact]
    public void RandomAccess_OverAPayloadWithNoChunks_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var file = Encrypted(identity, 32);

        // Keep the header and the 16-byte payload nonce, drop every chunk.
        var headerEnd = FindPayloadStart(file);
        var truncated = file[..(headerEnd + 16)];

        Assert.Throws<AgePayloadException>(() =>
        {
            using var source = new MemoryStream(truncated);
            using var reader = new AgeRandomAccess(source, identity);
        });
    }

    [Fact]
    public void RandomAccess_OverAChunkTooSmallForItsTag_IsRejected()
    {
        using var identity = X25519Identity.Generate();
        var file = Encrypted(identity, 32);

        // A payload of fewer than 16 bytes cannot even hold an authentication tag.
        var headerEnd = FindPayloadStart(file);
        var truncated = file[..(headerEnd + 16 + 8)];

        Assert.Throws<AgePayloadException>(() =>
        {
            using var source = new MemoryStream(truncated);
            using var reader = new AgeRandomAccess(source, identity);
        });
    }

    // The payload begins immediately after the header's MAC line.
    private static int FindPayloadStart(byte[] file)
    {
        var text = System.Text.Encoding.ASCII.GetString(file);
        var macLine = text.IndexOf("--- ", StringComparison.Ordinal);

        return text.IndexOf('\n', macLine) + 1;
    }

    // H6 — deriving the post-quantum recipient runs a full ML-KEM-768 key generation, and it was
    // re-run on every access, so decrypting an N-stanza header cost N keygens. Caching makes that
    // one. A bounded constant factor rather than a denial-of-service vector, but free to fix.
    [Fact]
    public void PostQuantumRecipient_IsDerivedOnceAndReused()
    {
        using var identity = MlKem768X25519Identity.Generate();

        var first = identity.Recipient;
        var second = identity.Recipient;

        Assert.Same(first, second);
        Assert.Equal(first.ToString(), second.ToString());
    }

    [Fact]
    public void PostQuantumRecipient_IsStillGuardedAfterDispose()
    {
        var identity = MlKem768X25519Identity.Generate();
        _ = identity.Recipient; // populate the cache first

        identity.Dispose();

        // The cache must not become a way to reach a disposed identity's derived key.
        Assert.Throws<ObjectDisposedException>(() => identity.Recipient);
    }

    // --- The span-filling encoder's own guard ---

    [Fact]
    public void EncodeIntoTooSmallABuffer_Throws()
    {
        var data = new byte[32];

        Assert.Throws<InvalidOperationException>(() => Base64Unpadded.Encode(data, new char[4]));
    }

    [Fact]
    public void EncodeIntoAnExactlySizedBuffer_Works()
    {
        var data = new byte[16];
        var destination = new char[Base64Unpadded.MaxEncodedLength(data.Length)];

        var written = Base64Unpadded.Encode(data, destination);

        Assert.Equal(Base64Unpadded.Encode(data), new string(destination, 0, written));
    }

    [Fact]
    public void EncodeOfNothingWritesNothing()
    {
        Assert.Equal(0, Base64Unpadded.Encode([], new char[4]));
    }
}
