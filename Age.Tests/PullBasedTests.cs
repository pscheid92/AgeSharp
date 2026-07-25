using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

public class PullBasedTests
{
    [Fact]
    public void EncryptReader_Decrypt_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "pull-based encrypt test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, identity.Recipient);

        // Read all encrypted data
        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        // Decrypt with push-based API
        ciphertext.Position = 0;
        using var output = new MemoryStream();
        Age.Decrypt(ciphertext, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Encrypt_DecryptReader_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "pull-based decrypt test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var ciphertext = new MemoryStream();
        Age.Encrypt(input, ciphertext, identity.Recipient);

        ciphertext.Position = 0;
        using var decryptedStream = Age.DecryptReader(ciphertext, identity);

        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void BothPullBased_RoundTrip()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "both pull-based"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, identity.Recipient);

        // Pipe encrypted reader into decrypt reader
        using var ciphertextBuffer = new MemoryStream();
        encryptedStream.CopyTo(ciphertextBuffer);
        ciphertextBuffer.Position = 0;

        using var decryptedStream = Age.DecryptReader(ciphertextBuffer, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void PartialReads_OneByteAtATime()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "byte by byte"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, identity.Recipient);

        // Read encrypted data one byte at a time
        using var ciphertext = new MemoryStream();
        var buf = new byte[1];
        int read;
        while ((read = encryptedStream.Read(buf, 0, 1)) > 0)
            ciphertext.Write(buf, 0, read);

        // Decrypt
        ciphertext.Position = 0;
        using var decryptedStream = Age.DecryptReader(ciphertext, identity);

        // Also read decrypted one byte at a time
        using var output = new MemoryStream();
        while ((read = decryptedStream.Read(buf, 0, 1)) > 0)
            output.Write(buf, 0, read);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void LargeFile_MultiChunk()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[100_000];
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var decryptedStream = Age.DecryptReader(ciphertext, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void EmptyPlaintext()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = Array.Empty<byte>();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var decryptedStream = Age.DecryptReader(ciphertext, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Armored_EncryptReader()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "armored pull test"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var output = new MemoryStream();
        Age.Decrypt(ciphertext, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void EncryptReader_CanSeekIsFalse()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream("test"u8.ToArray());
        using var stream = Age.EncryptReader(input, identity.Recipient);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptReader_UnsupportedMembers_Throw(bool armored)
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream("data"u8.ToArray());
        using var stream = Age.EncryptReader(input, new AgeEncryptOptions { Armor = armored }, identity.Recipient);

        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => _ = stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        stream.Flush(); // no-op
    }

    [Fact]
    public void DecryptReader_SeekableSource_IsSeekable()
    {
        using var identity = X25519Identity.Generate();

        using var input = new MemoryStream("test"u8.ToArray());
        using var ciphertext = new MemoryStream();
        Age.Encrypt(input, ciphertext, identity.Recipient);

        ciphertext.Position = 0;
        using var stream = Age.DecryptReader(ciphertext, identity);

        // CanSeek mirrors the source: a seekable MemoryStream yields a seekable stream.
        Assert.True(stream.CanRead);
        Assert.True(stream.CanSeek);
        Assert.False(stream.CanWrite);
    }

    [Fact]
    public void ExactChunkSize()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[64 * 1024]; // Exactly one chunk
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var decryptedStream = Age.DecryptReader(ciphertext, identity);
        using var output = new MemoryStream();
        decryptedStream.CopyTo(output);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Armored_EncryptReader_LargePlaintext_RoundTrip()
    {
        // > 1 MiB forces EncryptStream to produce multiple chunks, and
        // ArmorStream to cycle Begin → Body (many times) → End.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[1_500_000];
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var ciphertext = new MemoryStream();
        encryptedStream.CopyTo(ciphertext);

        ciphertext.Position = 0;
        using var output = new MemoryStream();
        Age.Decrypt(ciphertext, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Armored_EncryptReader_ByteByByteReads_RoundTrip()
    {
        // Stresses ArmorStream's scratch-drain loop: each Read call
        // takes exactly one byte, crossing Begin/Body/End boundaries
        // mid-scratch.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[500];
        new Random(42).NextBytes(plaintext);

        using var input = new MemoryStream(plaintext);
        using var encryptedStream = Age.EncryptReader(input, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var ciphertext = new MemoryStream();
        var oneByte = new byte[1];
        while (encryptedStream.Read(oneByte, 0, 1) == 1)
            ciphertext.WriteByte(oneByte[0]);

        ciphertext.Position = 0;
        using var output = new MemoryStream();
        Age.Decrypt(ciphertext, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void Armored_EncryptReader_MatchesPushArmor_ByteForByte()
    {
        // ArmorStream (pull) and AsciiArmor.Armor (push) must produce
        // identical wire output for the same ciphertext. Use a fixed
        // file key / payload nonce via deterministic inputs isn't
        // practical, so we compare two outputs from the same plaintext
        // through each path — they differ only in the recipient stanza
        // (random ephemeral key) and payload nonce (random). So we
        // compare *lengths* and re-encrypt round-trip shape. The
        // stronger invariant — that both decrypt back to the same
        // plaintext — is implied by the other two tests passing.
        //
        // Here we instead check a tighter invariant: feed a fixed byte
        // stream directly to both ArmorStream and AsciiArmor.Armor and
        // require byte-identical output.
        var fixedCiphertext = new byte[200_000];
        new Random(7).NextBytes(fixedCiphertext);

        using var pullSource = new MemoryStream(fixedCiphertext);
        using var pullArmor = new AgeSharp.ArmorStream(pullSource);
        using var pullOut = new MemoryStream();
        pullArmor.CopyTo(pullOut);

        using var pushSource = new MemoryStream(fixedCiphertext);
        using var pushOut = new MemoryStream();
        AgeSharp.AsciiArmor.Armor(pushSource, pushOut);

        Assert.Equal(pushOut.ToArray(), pullOut.ToArray());
    }
}
