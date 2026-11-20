using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Armor is detected by reading ahead, not by seeking, so armored input from a pipe or a network
/// stream decrypts as it does from a file. Detection reads only as far as it needs: a binary file
/// read from a pipe is left exactly where reading its header ends.
/// </summary>
public class ArmoredOnAPipeTests
{
    private static readonly byte[] Plaintext = "carried over a pipe"u8.ToArray();

    [Fact]
    public void ArmoredInputOnAPipe_Decrypts()
    {
        using var identity = X25519Identity.Generate();
        using var output = new MemoryStream();

        new Identities(identity).Decrypt(new Pipe(Encrypt(identity, armor: true)), output);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Fact]
    public void ArmoredInputOnAPipe_DecryptsThroughTheReaderToo()
    {
        using var identity = X25519Identity.Generate();
        using var reader = new Identities(identity).DecryptReader(new Pipe(Encrypt(identity, armor: true)));
        using var output = new MemoryStream();

        reader.CopyTo(output);

        Assert.Equal(Plaintext, output.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AHeaderOnAPipe_IsReadAsFromAFile(bool armor)
    {
        using var identity = X25519Identity.Generate();
        var file = Encrypt(identity, armor);

        var fromFile = AgeHeader.Parse(new MemoryStream(file));
        var fromPipe = AgeHeader.Parse(new Pipe(file));

        Assert.Equal(armor, fromPipe.IsArmored);
        Assert.Equal(fromFile.IsArmored, fromPipe.IsArmored);
        Assert.Equal(fromFile.PayloadOffset, fromPipe.PayloadOffset);
        Assert.Equal(fromFile.Recipients.Select(s => s.Type), fromPipe.Recipients.Select(s => s.Type));
    }

    // Detection may not swallow bytes that are not its business: after the header of a binary
    // file, a pipe is where it would be had nothing looked ahead.
    [Fact]
    public void ReadingABinaryHeaderFromAPipe_LeavesThePipeAtThePayload()
    {
        using var identity = X25519Identity.Generate();
        var file = Encrypt(identity, armor: false);
        var pipe = new Pipe(file);

        var header = AgeHeader.Parse(pipe);

        Assert.Equal(file.Length - header.PayloadOffset, pipe.Remaining);
    }

    [Fact]
    public void LeadingWhitespaceBeforeArmor_IsAllowedOnAPipe()
    {
        using var identity = X25519Identity.Generate();
        using var output = new MemoryStream();

        new Identities(identity).Decrypt(new Pipe([.. "\n\n  \n"u8, .. Encrypt(identity, armor: true)]), output);

        Assert.Equal(Plaintext, output.ToArray());
    }

    // Whitespace beyond what armor allows is refused by the armor reader, with the same
    // reason on a pipe as from a file, however far detection would have had to look.
    [Theory]
    [InlineData(2_000)]
    [InlineData(4_200)]
    [InlineData(10_000)]
    public void TooMuchLeadingWhitespace_IsRefusedAsFromAFile(int newlines)
    {
        using var identity = X25519Identity.Generate();
        byte[] file = [.. Enumerable.Repeat((byte)'\n', newlines), .. Encrypt(identity, armor: true)];

        var fromFile = Assert.Throws<AgeArmorException>(() => new Identities(identity).Decrypt(new MemoryStream(file), new MemoryStream()));
        var fromPipe = Assert.Throws<AgeArmorException>(() => new Identities(identity).Decrypt(new Pipe(file), new MemoryStream()));

        Assert.Equal(fromFile.Message, fromPipe.Message);
    }

    // Nothing but whitespace is not armor, and not an age file either.
    [Fact]
    public void OnlyWhitespace_IsNotArmor()
    {
        var header = Assert.Throws<AgeHeaderException>(() => AgeHeader.Parse(new Pipe("\n \n\t\n"u8.ToArray())));

        Assert.DoesNotContain("armor", header.Message, StringComparison.OrdinalIgnoreCase);
    }

    // A genuinely wrong version line must still report a version problem.
    [Fact]
    public void AnActuallyUnsupportedVersion_StillReportsTheVersion()
    {
        using var identity = X25519Identity.Generate();
        var file = System.Text.Encoding.ASCII.GetBytes("age-encryption.org/v2\n--- AAAA\n");

        var ex = Assert.Throws<AgeHeaderException>(() => new Identities(identity).Decrypt(new Pipe(file), new MemoryStream()));

        Assert.Contains("unsupported version", ex.Message, StringComparison.Ordinal);
    }

    // A detached header is binary by definition; armor there is named, not blamed on the version.
    [Fact]
    public void AnArmoredDetachedHeader_IsNamedAsArmor()
    {
        using var identity = X25519Identity.Generate();
        var armored = Encrypt(identity, armor: true);

        var ex = Assert.Throws<AgeHeaderException>(() =>
            new Identities(identity).DecryptDetached(new MemoryStream(armored), new MemoryStream(), new MemoryStream()));

        Assert.Contains("ASCII-armored", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("seekable", ex.Message, StringComparison.Ordinal);
    }

    private static byte[] Encrypt(X25519Identity identity, bool armor)
    {
        using var output = new MemoryStream();
        new Recipients(identity.Recipient).Encrypt(new MemoryStream(Plaintext), output, new AgeEncryptOptions { Armor = armor });
        return output.ToArray();
    }

    // A stream that cannot seek, like a pipe or a network socket, and reports how much is left.
    private sealed class Pipe(byte[] data) : Stream
    {
        private readonly MemoryStream _inner = new(data);

        public long Remaining => _inner.Length - _inner.Position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
