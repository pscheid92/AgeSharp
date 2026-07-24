using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Contracts of the two internal read-only wrappers the armor path is built on:
/// <c>PeekableStream</c> (lookahead that can be replayed, which is what lets armor
/// detection work without seeking) and <c>NewlineBoundedStream</c> (caps how many
/// bytes may pass without a line terminator).
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

    // --- NewlineBoundedStream ---

    [Fact]
    public void LinesWithinTheBound_PassThroughUnchanged()
    {
        var source = "aaaa\nbbbb\ncccc"u8.ToArray();
        using var bounded = new NewlineBoundedStream(new MemoryStream(source), maxLineBytes: 8);

        using var drained = new MemoryStream();
        bounded.CopyTo(drained);
        Assert.Equal(source, drained.ToArray());
    }

    [Fact]
    public void SpanRead_AlsoPassesThrough_AndEnforcesTheBound()
    {
        // The span overload is the one StreamReader actually drives, so it needs the
        // same scan as the byte[] path rather than inheriting the base implementation.
        var source = "aaaa\nbbbb\n"u8.ToArray();
        using var ok = new NewlineBoundedStream(new MemoryStream(source), maxLineBytes: 8);

        Span<byte> buffer = stackalloc byte[4];
        var total = 0;
        int n;
        while ((n = ok.Read(buffer)) > 0)
            total += n;

        Assert.Equal(source.Length, total);

        var unterminated = new byte[256];
        Array.Fill(unterminated, (byte)'A');
        using var tooLong = new NewlineBoundedStream(new MemoryStream(unterminated), maxLineBytes: 32);

        Assert.Throws<AgeFormatException>(() =>
        {
            Span<byte> b = stackalloc byte[64];
            while (tooLong.Read(b) > 0) { }
        });
    }

    [Fact]
    public void ALineLongerThanTheBound_Throws()
    {
        var source = new byte[4096];             // no newline anywhere
        Array.Fill(source, (byte)'A');
        using var bounded = new NewlineBoundedStream(new MemoryStream(source), maxLineBytes: 64);

        Assert.Throws<AgeFormatException>(() =>
        {
            using var drained = new MemoryStream();
            bounded.CopyTo(drained);
        });
    }

    [Fact]
    public void ALineSplitAcrossReads_StillTripsTheBound()
    {
        // The run has to be carried between reads, or a long line slips through
        // whenever it straddles a buffer boundary.
        var source = new byte[300];
        Array.Fill(source, (byte)'A');
        using var bounded = new NewlineBoundedStream(new MemoryStream(source), maxLineBytes: 100);

        var buffer = new byte[64];
        Assert.Throws<AgeFormatException>(() =>
        {
            while (bounded.Read(buffer, 0, buffer.Length) > 0) { }
        });
    }

    [Fact]
    public void NewlineBoundedStream_IsForwardOnlyAndReadOnly()
    {
        using var bounded = new NewlineBoundedStream(new MemoryStream([1]), maxLineBytes: 8);

        Assert.True(bounded.CanRead);
        Assert.False(bounded.CanSeek);
        Assert.False(bounded.CanWrite);
        bounded.Flush();

        Assert.Throws<NotSupportedException>(() => bounded.Length);
        Assert.Throws<NotSupportedException>(() => bounded.Position);
        Assert.Throws<NotSupportedException>(() => bounded.Position = 0);
        Assert.Throws<NotSupportedException>(() => bounded.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => bounded.SetLength(1));
        Assert.Throws<NotSupportedException>(() => bounded.Write(new byte[1], 0, 1));
    }

    [Fact]
    public void NewlineBoundedStream_DoesNotDisposeTheWrappedStream()
    {
        var inner = new MemoryStream([1, 2, 3]);
        using (var bounded = new NewlineBoundedStream(inner, maxLineBytes: 8))
            bounded.CopyTo(Stream.Null);

        Assert.True(inner.CanRead);
        inner.Position = 0;
    }
}
