using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// I1 (message half) — armor is auto-detected only on a seekable stream, so armored input from a
/// pipe reaches the binary header parser intact and its BEGIN marker was reported as an
/// "unsupported version". Supporting non-seekable armor outright widens what a patch release
/// accepts, against the documented behaviour, so only the diagnosis is fixed here.
/// </summary>
public class ArmoredOnAPipeTests
{
    // A stream that refuses to seek, like a pipe or a network socket.
    private sealed class NonSeekableStream(byte[] data) : Stream
    {
        private readonly MemoryStream _inner = new(data);

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

    [Fact]
    public void ArmoredInputOnANonSeekableStream_SaysSoInsteadOfBlamingTheVersion()
    {
        using var identity = X25519Identity.Generate();

        using var input = new MemoryStream("hello"u8.ToArray());
        using var armored = new MemoryStream();
        AgeEncrypt.Encrypt(input, armored, armor: true, identity.Recipient);

        using var pipe = new NonSeekableStream(armored.ToArray());
        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(pipe, output, identity));

        Assert.Contains("ASCII-armored", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("unsupported version", ex.Message, StringComparison.Ordinal);
    }

    // A genuinely wrong version line must still report a version problem.
    [Fact]
    public void AnActuallyUnsupportedVersion_StillReportsTheVersion()
    {
        using var identity = X25519Identity.Generate();
        var file = System.Text.Encoding.ASCII.GetBytes("age-encryption.org/v2\n--- AAAA\n");

        using var source = new MemoryStream(file);
        using var output = new MemoryStream();

        var ex = Assert.Throws<AgeHeaderException>(() => AgeEncrypt.Decrypt(source, output, identity));

        Assert.Contains("unsupported version", ex.Message, StringComparison.Ordinal);
    }

    // Armored input on a seekable stream is detected and decrypts normally — unchanged.
    [Fact]
    public void ArmoredInputOnASeekableStream_StillDecrypts()
    {
        using var identity = X25519Identity.Generate();
        var plaintext = "hello"u8.ToArray();

        using var input = new MemoryStream(plaintext);
        using var armored = new MemoryStream();
        AgeEncrypt.Encrypt(input, armored, armor: true, identity.Recipient);

        using var source = new MemoryStream(armored.ToArray());
        using var output = new MemoryStream();
        AgeEncrypt.Decrypt(source, output, identity);

        Assert.Equal(plaintext, output.ToArray());
    }
}
