using System.Text;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Geometry resolution and the fallbacks around it. Every case where the layout
///     cannot be trusted must yield a forward-only stream rather than a seekable one
///     with wrong offsets — falling back is always safe, guessing is not.
/// </summary>
public class ArmorGeometryTests
{
    private static Stream Dearmor(string text)
    {
        return AsciiArmor.Dearmor(new MemoryStream(Encoding.ASCII.GetBytes(text)),
            new AgeDecryptOptions().MaxArmorLineBytes);
    }

    private static string Armor(params string[] bodyLines)
    {
        return "-----BEGIN AGE ENCRYPTED FILE-----\n"
               + string.Concat(bodyLines.Select(l => l + "\n"))
               + "-----END AGE ENCRYPTED FILE-----\n";
    }

    // --- resolvable ----------------------------------------------------------

    [Fact]
    public void WellFormedArmor_IsSeekable()
    {
        using var stream = Dearmor(Armor(new string('A', 64), new string('A', 64), "AAAA"));

        Assert.True(stream.CanSeek);
        Assert.Equal(48 + 48 + 3, stream.Length);
    }

    [Fact]
    public void SingleFullLine_IsSeekable()
    {
        using var stream = Dearmor(Armor(new string('A', 64)));

        Assert.True(stream.CanSeek);
        Assert.Equal(48, stream.Length);
    }

    [Fact]
    public void FullWidthPaddedFinalLine_LengthAccountsForPadding()
    {
        // The regression from #86, now on the geometry side: a full-width final line
        // decodes to 46 or 47 bytes, so Length cannot assume 48 per line.
        using var stream = Dearmor(Armor(new string('A', 64), new string('A', 62) + "=="));

        Assert.True(stream.CanSeek);
        Assert.Equal(48 + 46, stream.Length);
    }

    // --- unresolvable: must fall back, never guess ---------------------------

    [Fact]
    public void EmptySource_IsNotSeekable()
    {
        using var stream = Dearmor("");
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void NonWhitespaceBeforeTheMarker_IsNotSeekable()
    {
        // Detection may still have accepted this, but the offsets would be anchored
        // to the wrong place, so geometry declines.
        using var stream = Dearmor("junk\n" + Armor(new string('A', 64)));
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void MarkerWithoutATerminator_IsNotSeekable()
    {
        using var stream = Dearmor("-----BEGIN AGE ENCRYPTED FILE-----");
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void MissingEndMarker_IsNotSeekable()
    {
        using var stream = Dearmor("-----BEGIN AGE ENCRYPTED FILE-----\n" + new string('A', 64) + "\n");
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void TrailingDataAfterTheEndMarker_IsNotSeekable()
    {
        using var stream = Dearmor(Armor(new string('A', 64)) + "trailing junk\n");
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void EmptyBody_IsNotSeekable()
    {
        using var stream = Dearmor("-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n");
        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void NonSeekableSource_IsNotSeekable()
    {
        using var inner = new MemoryStream(Encoding.ASCII.GetBytes(Armor(new string('A', 64))));
        using var stream = AsciiArmor.Dearmor(new NonSeekableStream(inner));

        Assert.False(stream.CanSeek);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
    }

    // --- seek origins on the dearmor stream itself ---------------------------

    [Fact]
    public void SeekOrigins_AllResolveToTheSameByte()
    {
        // The decrypt stream above only ever sets Position, so the Current and End
        // branches are reached solely through direct use.
        var body = new[] { new string('A', 64), new string('B', 64), "AAAA" };
        using var stream = Dearmor(Armor(body));

        var expected = new byte[3];
        stream.Position = 50;
        stream.ReadExactly(expected);

        var viaCurrent = new byte[3];
        stream.Position = 20;
        stream.Seek(30, SeekOrigin.Current);
        stream.ReadExactly(viaCurrent);

        var viaEnd = new byte[3];
        stream.Seek(50 - stream.Length, SeekOrigin.End);
        stream.ReadExactly(viaEnd);

        Assert.Equal(expected, viaCurrent);
        Assert.Equal(expected, viaEnd);
    }

    [Fact]
    public void SeekReportsTheRequestedPosition_NotTheLineStart()
    {
        // Regression: the sub-line remainder is skipped lazily, and Position used to
        // report the line start until that skip happened — which made the next
        // relative seek land mid-line.
        using var stream = Dearmor(Armor(new string('A', 64), new string('B', 64), "AAAA"));

        var position = stream.Seek(50, SeekOrigin.Begin);

        Assert.Equal(50, position);
        Assert.Equal(50, stream.Position);
    }

    [Fact]
    public void NegativeSeek_Throws()
    {
        using var stream = Dearmor(Armor(new string('A', 64)));
        Assert.Throws<ArgumentOutOfRangeException>(() => stream.Seek(-1, SeekOrigin.Begin));
    }

    [Fact]
    public void InvalidSeekOrigin_Throws()
    {
        using var stream = Dearmor(Armor(new string('A', 64)));
        Assert.Throws<ArgumentOutOfRangeException>(() => stream.Seek(0, (SeekOrigin)99));
    }

    [Fact]
    public void SourceThatOverstatesItsLength_FallsBackRatherThanThrowing()
    {
        // The probes are sized from Stream.Length. A stream that claims more than it
        // can deliver would otherwise fault mid-probe; geometry treats the short read
        // as "cannot resolve" and hands back a forward-only stream.
        var text = Encoding.ASCII.GetBytes(Armor(new string('A', 64), "AAAA"));
        using var lying = new OverstatedLengthStream(new MemoryStream(text), text.Length + 4096);
        using var stream = AsciiArmor.Dearmor(lying);

        Assert.False(stream.CanSeek);
    }

    [Fact]
    public async Task AsyncResolution_FallsBackOnAShortSourceToo()
    {
        // Same guard on the asynchronous probe, which is a separate read path.
        var text = Encoding.ASCII.GetBytes(Armor(new string('A', 64), "AAAA"));
        using var lying = new OverstatedLengthStream(new MemoryStream(text), text.Length + 4096);
        using var stream = await AsciiArmor.DearmorAsync(lying, 65536, CancellationToken.None);

        Assert.False(stream.CanSeek);
    }

    [Fact]
    public void FinalLineWithoutATrailingNewline_StillDecodes()
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\n"
                   + new string('A', 64) + "\n"
                   + "-----END AGE ENCRYPTED FILE-----"; // no trailing newline

        using var stream = Dearmor(text);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(48, output.Length);
    }

    [Fact]
    public void CrlfTerminators_ChangeTheStride()
    {
        var text = "-----BEGIN AGE ENCRYPTED FILE-----\r\n"
                   + new string('A', 64) + "\r\n"
                   + "AAAA\r\n"
                   + "-----END AGE ENCRYPTED FILE-----\r\n";

        using var stream = Dearmor(text);

        Assert.True(stream.CanSeek);
        Assert.Equal(48 + 3, stream.Length);
    }

    private sealed class OverstatedLengthStream(Stream inner, long claimedLength) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => claimedLength;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = Math.Min(value, inner.Length);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return inner.Read(buffer, offset, count);
        }

        public override int Read(Span<byte> buffer)
        {
            return inner.Read(buffer);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return inner.Seek(offset, origin);
        }

        public override void Flush()
        {
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}