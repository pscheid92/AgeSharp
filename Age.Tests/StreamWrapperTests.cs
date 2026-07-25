using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Contract of <c>PeekableStream</c>: lookahead that can be replayed, which is what
///     lets armor detection work without seeking.
/// </summary>
public class StreamWrapperTests
{
    private static byte[] Bytes(params byte[] values)
    {
        return values;
    }

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
        var first = peekable.Read(buffer, 0, 4); // replayed prefix
        var second = peekable.Read(buffer, first, 4 - first); // passed through

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

    // Peeking twice must top the buffer up, not replace it. Replacing would drop the
    // bytes the first peek pulled from the source but the caller has not read yet —
    // and those bytes are unrecoverable, because the source has already yielded them.
    [Fact]
    public void PeekableStream_PeekingTwice_KeepsEveryByte()
    {
        using var peekable = new PeekableStream(new MemoryStream([1, 2, 3, 4, 5, 6]));

        Span<byte> first = stackalloc byte[2];
        Assert.Equal(2, peekable.Peek(first));
        Assert.Equal<byte[]>([1, 2], first.ToArray());

        Span<byte> second = stackalloc byte[4];
        Assert.Equal(4, peekable.Peek(second));
        Assert.Equal([1, 2, 3, 4], second.ToArray());

        var all = new byte[6];
        var total = 0;
        while (total < all.Length)
        {
            var read = peekable.Read(all.AsSpan(total));
            if (read == 0)
                break;

            total += read;
        }

        Assert.Equal([1, 2, 3, 4, 5, 6], all);
    }

    [Fact]
    public async Task PeekableStream_PeekingTwiceAsync_KeepsEveryByte()
    {
        using var peekable = new PeekableStream(new MemoryStream([1, 2, 3, 4, 5, 6]));

        var first = new byte[2];
        Assert.Equal(2, await peekable.PeekAsync(first));

        var second = new byte[4];
        Assert.Equal(4, await peekable.PeekAsync(second));
        Assert.Equal([1, 2, 3, 4], second);

        var all = new byte[6];
        var total = 0;
        while (total < all.Length)
        {
            var read = await peekable.ReadAsync(all.AsMemory(total));
            if (read == 0)
                break;

            total += read;
        }

        Assert.Equal([1, 2, 3, 4, 5, 6], all);
    }
}