using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// Armor is auto-detected only on a seekable stream, so the CLI buffers input that cannot seek —
/// and only that. It used to copy every input into a MemoryStream, so decrypting a file cost its
/// full size in memory, and anything over 2 GiB, MemoryStream's limit, failed outright.
/// </summary>
public sealed class SeekableInputTests : IDisposable
{
    private readonly string _path = Path.GetTempFileName();

    public void Dispose() => File.Delete(_path);

    [Fact]
    public void SeekableInput_IsUsedInPlace()
    {
        File.WriteAllBytes(_path, [1, 2, 3]);
        using var file = File.OpenRead(_path);

        Assert.Same(file, SeekableInput.From(file));
    }

    [Fact]
    public void UnseekableInput_IsBufferedWhole()
    {
        byte[] contents = [.. Enumerable.Range(0, 100_000).Select(i => (byte)i)];
        using var pipe = new UnseekableStream(new MemoryStream(contents));

        using var input = SeekableInput.From(pipe);

        Assert.True(input.CanSeek);
        Assert.Equal(0, input.Position);
        Assert.Equal(contents, ((MemoryStream)input).ToArray());
    }

    private sealed class UnseekableStream(Stream inner) : Stream
    {
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
