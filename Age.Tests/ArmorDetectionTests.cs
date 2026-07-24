using System.Text;
using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Armor detection uses lookahead rather than seeking, so armored input is
/// recognised on any stream — a pipe, a socket, an HTTP response body — not just
/// on one that happens to support <see cref="Stream.Seek"/>.
/// </summary>
public class ArmorDetectionTests
{
    private static readonly byte[] Plaintext = "armored over a pipe"u8.ToArray();

    [Fact]
    public void Decrypt_ArmoredNonSeekableSource_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(armored));
        using var output = new MemoryStream();
        Age.Decrypt(input, output, identity);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void OpenRead_ArmoredNonSeekableSource_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(armored));
        using var stream = Age.OpenRead(input, identity);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public async Task DecryptAsync_ArmoredNonSeekableSource_RoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(armored));
        using var output = new MemoryStream();
        await Age.DecryptAsync(input, output, [identity]);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void ReadHeader_ArmoredNonSeekableSource_Parses()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(armored));
        var header = Age.ReadHeader(input);

        Assert.True(header.IsArmored);
        Assert.Single(header.Stanzas);
        Assert.Equal("X25519", header.Stanzas[0].Type);
    }

    [Fact]
    public void BinarySource_StillRoundTrips_OverANonSeekableStream()
    {
        // Detection must not disturb the bytes it probes.
        using var identity = X25519Identity.Generate();
        var binary = Age.Encrypt(Plaintext, identity.Recipient);

        using var input = new NonSeekableStream(new MemoryStream(binary));
        using var output = new MemoryStream();
        Age.Decrypt(input, output, identity);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void BinarySeekableSource_KeepsRandomAccess()
    {
        // Probing a seekable source must rewind it, leaving seekability intact —
        // otherwise detection would cost every binary file its random access.
        using var identity = X25519Identity.Generate();
        var plaintext = new byte[200_000];
        new Random(7).NextBytes(plaintext);
        var binary = Age.Encrypt(plaintext, identity.Recipient);

        using var input = new MemoryStream(binary);
        using var stream = Age.OpenRead(input, identity);

        Assert.True(stream.CanSeek);
        Assert.Equal(plaintext.Length, stream.Length);

        stream.Seek(150_000, SeekOrigin.Begin);
        var buffer = new byte[100];
        stream.ReadExactly(buffer);
        Assert.Equal(plaintext.AsSpan(150_000, 100).ToArray(), buffer);
    }

    // --- the source stream is never disposed by the library ---

    [Fact]
    public void ReadHeader_DoesNotDisposeAnArmoredSource()
    {
        // The dearmor chain used to own its source, so inspecting an armored file's
        // header closed the caller's stream.
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new MemoryStream(armored);
        Age.ReadHeader(input);

        Assert.True(input.CanRead);
        input.Position = 0;
    }

    [Fact]
    public void Decrypt_DoesNotDisposeAnArmoredSource()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);

        using var input = new MemoryStream(armored);
        using (var output = new MemoryStream())
            Age.Decrypt(input, output, identity);

        Assert.True(input.CanRead);
        input.Position = 0;
    }

    // --- leading whitespace, bounded ---

    [Fact]
    public void LeadingWhitespace_WithinTheBound_IsStillDetected()
    {
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
        var padded = (byte[])[.. Encoding.ASCII.GetBytes(new string('\n', 512)), .. armored];

        using var input = new NonSeekableStream(new MemoryStream(padded));
        using var output = new MemoryStream();
        Age.Decrypt(input, output, identity);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void LeadingWhitespace_BeyondTheBound_IsNotTreatedAsArmor()
    {
        // A fixed-size probe is what lets detection work without seeking; input that
        // pushes the marker past it is rejected rather than silently misread. The
        // reference CLI draws the same line at 1 KiB.
        using var identity = X25519Identity.Generate();
        var armored = Age.Encrypt(Plaintext, new AgeEncryptOptions { Armor = true }, identity.Recipient);
        var padded = (byte[])[.. Encoding.ASCII.GetBytes(new string('\n', 4096)), .. armored];

        using var input = new NonSeekableStream(new MemoryStream(padded));
        using var output = new MemoryStream();

        Assert.Throws<AgeFormatException>(() => Age.Decrypt(input, output, identity));
    }
}
