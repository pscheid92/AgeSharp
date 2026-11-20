using Age.Format;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Looking ahead on a stream that cannot seek: what is looked at is replayed to the reads that
/// follow, and the source is never read further than what was asked to be looked at.
/// </summary>
public class PeekableStreamTests
{
    private static readonly byte[] Data = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();

    [Fact]
    public void LookingFurther_ReadsOnlyWhatIsNew()
    {
        var source = new MemoryStream(Data);
        var peekable = new PeekableStream(source);

        Assert.Equal(Data[..30], peekable.Peek(30).ToArray());
        Assert.Equal(30, source.Position);

        Assert.Equal(Data[..31], peekable.Peek(31).ToArray());
        Assert.Equal(31, source.Position);

        Assert.Equal(Data[..100], peekable.Peek(100).ToArray());
        Assert.Equal(100, source.Position);
    }

    [Fact]
    public void LookingAgainWithinWhatWasLookedAt_ReadsNothingNew()
    {
        var source = new MemoryStream(Data);
        var peekable = new PeekableStream(source);
        peekable.Peek(30);
        peekable.ReadByte();

        Assert.Equal(Data[1..11], peekable.Peek(10).ToArray());
        Assert.Equal(30, source.Position);
    }

    [Fact]
    public void ItReadsOnly_ItCannotSeekOrWrite()
    {
        var peekable = new PeekableStream(new MemoryStream(Data));

        Assert.True(peekable.CanRead);
        Assert.False(peekable.CanSeek);
        Assert.False(peekable.CanWrite);
        Assert.Throws<NotSupportedException>(() => peekable.Length);
        Assert.Throws<NotSupportedException>(() => peekable.Position);
        Assert.Throws<NotSupportedException>(() => peekable.Position = 0);
        Assert.Throws<NotSupportedException>(() => peekable.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => peekable.SetLength(0));
        Assert.Throws<NotSupportedException>(() => peekable.Write([1], 0, 1));
        peekable.Flush();
    }

    [Fact]
    public void WhatWasLookedAt_IsReadAgain_ThenTheRest()
    {
        var peekable = new PeekableStream(new MemoryStream(Data));
        peekable.Peek(10);

        Assert.Equal(Data[0], peekable.ReadByte());

        var rest = new MemoryStream();
        peekable.CopyTo(rest);
        Assert.Equal(Data[1..], rest.ToArray());
    }

    [Fact]
    public async Task WhatWasLookedAt_IsReadAgain_Asynchronously()
    {
        var peekable = new PeekableStream(new MemoryStream(Data));
        peekable.Peek(10);

        var first = new byte[4];
        Assert.Equal(4, await peekable.ReadAsync(first, 0, 4, CancellationToken.None));

        var rest = new MemoryStream();
        await peekable.CopyToAsync(rest);

        byte[] all = [.. first, .. rest.ToArray()];
        Assert.Equal(Data, all);
    }

    [Fact]
    public void LookingPastTheEnd_GivesWhatThereIs()
    {
        var peekable = new PeekableStream(new MemoryStream(Data[..5]));

        Assert.Equal(Data[..5], peekable.Peek(34).ToArray());
        Assert.Equal(Data[..5], peekable.Peek(34).ToArray());
        Assert.Equal(-1, ReadPast(peekable, 5));
    }

    private static int ReadPast(Stream stream, int count)
    {
        for (var i = 0; i < count; i++)
            stream.ReadByte();

        return stream.ReadByte();
    }
}
