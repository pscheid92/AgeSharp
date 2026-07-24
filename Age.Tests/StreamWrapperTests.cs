using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Contract of <c>PeekableStream</c>: lookahead that can be replayed, which is what
/// lets armor detection work without seeking.
/// </summary>
public class StreamWrapperTests
{
    private static byte[] Bytes(params byte[] values) => values;

    // --- PeekableStream ---

    [Fact]
    public void Peek_DoesNotConsume_TheBytesItReturns()
    {
        var source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        using var peekable = new PeekableStream(new MemoryStream(source));

        var probe = new byte[4];
        Assert.Equal(4, peekable.Peek(probe));
        Assert.Equal(Bytes(1, 2, 3, 4), probe);

        // Everything, including the probed prefix, must still be readable.
        using var drained = new MemoryStream();
        peekable.CopyTo(drained);
        Assert.Equal(source, drained.ToArray());
    }

    [Fact]
    public async Task PeekAsync_DoesNotConsume_TheBytesItReturns()
    {
        var source = new byte[] { 9, 8, 7, 6, 5 };
        await using var peekable = new PeekableStream(new MemoryStream(source));

        var probe = new byte[3];
        Assert.Equal(3, await peekable.PeekAsync(probe));
        Assert.Equal(Bytes(9, 8, 7), probe);

        using var drained = new MemoryStream();
        await peekable.CopyToAsync(drained);
        Assert.Equal(source, drained.ToArray());
    }

    [Fact]
    public void Peek_ShorterThanRequested_AtEndOfStream()
    {
        using var peekable = new PeekableStream(new MemoryStream([1, 2]));

        var probe = new byte[16];
        Assert.Equal(2, peekable.Peek(probe));

        using var drained = new MemoryStream();
        peekable.CopyTo(drained);
        Assert.Equal(Bytes(1, 2), drained.ToArray());
    }

    [Fact]
    public void Peek_OnAnEmptyStream_ReturnsZero()
    {
        using var peekable = new PeekableStream(new MemoryStream([]));

        Assert.Equal(0, peekable.Peek(new byte[8]));
        Assert.Equal(0, peekable.Read(new byte[8], 0, 8));
    }

    [Fact]
    public void Read_ByteArrayOverload_ReplaysThenPassesThrough()
    {
        using var peekable = new PeekableStream(new MemoryStream([1, 2, 3, 4]));
        peekable.Peek(new byte[2]);

        var buffer = new byte[4];
        var first = peekable.Read(buffer, 0, 4);      // replayed prefix
        var second = peekable.Read(buffer, first, 4 - first);  // passed through

        Assert.Equal(4, first + second);
        Assert.Equal(Bytes(1, 2, 3, 4), buffer);
    }

    [Fact]
    public async Task ReadAsync_ByteArrayOverload_ReplaysThenPassesThrough()
    {
        await using var peekable = new PeekableStream(new MemoryStream([5, 6, 7, 8]));
        await peekable.PeekAsync(new byte[2]);

        var buffer = new byte[4];
        var first = await peekable.ReadAsync(buffer, 0, 4);
        var second = await peekable.ReadAsync(buffer, first, 4 - first);

        Assert.Equal(4, first + second);
        Assert.Equal(Bytes(5, 6, 7, 8), buffer);
    }

    [Fact]
    public void Disposing_DoesNotDisposeTheWrappedStream()
    {
        // The library never disposes caller-supplied streams; this wrapper sits
        // directly on one during armor detection.
        var inner = new MemoryStream([1, 2, 3]);
        var peekable = new PeekableStream(inner);
        peekable.Peek(new byte[2]);
        peekable.Dispose();

        Assert.True(inner.CanRead);
        inner.Position = 0;
    }

    [Fact]
    public void PeekableStream_IsForwardOnlyAndReadOnly()
    {
        using var peekable = new PeekableStream(new MemoryStream([1]));

        Assert.True(peekable.CanRead);
        Assert.False(peekable.CanSeek);
        Assert.False(peekable.CanWrite);
        peekable.Flush();

        Assert.Throws<NotSupportedException>(() => peekable.Length);
        Assert.Throws<NotSupportedException>(() => peekable.Position);
        Assert.Throws<NotSupportedException>(() => peekable.Position = 0);
        Assert.Throws<NotSupportedException>(() => peekable.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => peekable.SetLength(1));
        Assert.Throws<NotSupportedException>(() => peekable.Write(new byte[1], 0, 1));
    }
}
