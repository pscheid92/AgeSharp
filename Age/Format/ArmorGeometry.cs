using System.Text;

namespace AgeSharp;

/// <summary>
/// The line geometry of an ASCII-armored file, resolved from a seekable source so a
/// binary offset can be translated to a text position without decoding anything in
/// between.
/// </summary>
/// <remarks>
/// <para>
/// Armor is an order-preserving, position-computable transform: every body line is
/// exactly <see cref="ArmorFormat.ColumnsPerLine"/> base64 characters decoding to
/// <see cref="ArmorFormat.BytesPerLine"/> bytes, and only the final line may be short. So binary
/// byte <c>i</c> lives on line <c>i / 48</c> at offset <c>i % 48</c>, and that line
/// starts at <c>BodyStart + (i / 48) * LineStride</c>. This is unlike compression,
/// which genuinely destroys random access.
/// </para>
/// <para>
/// Resolution is O(1), not a scan. rage reads the whole stream in blocks to find the
/// end because its armored reader only has <c>BufRead</c>; a seekable source lets us
/// read a bounded probe at each end instead — the head to find where the body starts
/// and how wide a line terminator is, the tail to find the end marker. Without that,
/// every armored open would pay a full extra pass just to learn its length, since
/// <see cref="Crypto.SeekableDecryptStream"/> needs it up front.
/// </para>
/// <para>
/// The geometry is trusted only as far as the AEAD allows: if a middle line is short,
/// making these offsets wrong, the bytes at the computed position fail authentication
/// rather than decoding to silent garbage.
/// </para>
/// </remarks>
internal sealed class ArmorGeometry
{
    // Bounds the head and tail probes: leading whitespace before the begin marker, and
    // trailing whitespace after the end marker. Named for what it bounds rather than
    // reusing "ProbeSize" — AsciiArmor has a probe of its own, sized for armor
    // *detection*, and one name meaning two different sizes in one feature area is a
    // trap rather than a convenience.
    private const int EdgeProbeSize = 8192;

    /// <summary>Absolute source offset of the first body character.</summary>
    public long BodyStart { get; private init; }

    /// <summary>Source bytes from one body line's start to the next (64 + terminator).</summary>
    public int LineStride { get; private init; }

    /// <summary>Total decoded bytes the body yields.</summary>
    public long DecodedLength { get; private init; }

    /// <summary>
    /// Resolves the geometry, or returns null when the source is not armor laid out
    /// the way this translation assumes. A null result is not an error: the caller
    /// falls back to forward-only decoding, which validates every line as it goes.
    /// </summary>
    public static ArmorGeometry? TryResolve(Stream source)
    {
        var resolved = TryResolveCore(source, static (s, p, c) =>
        {
            s.Position = p;
            return ValueTask.FromResult(ReadFully(s, c));
        });

        // Every read above is synchronous, so the shared core completes before it
        // returns and reading the result never blocks. Guarded rather than assumed:
        // if a genuinely asynchronous step is ever added to Resolve, this fails here
        // and now instead of quietly blocking the caller's thread.
        if (!resolved.IsCompleted)
            throw new InvalidOperationException(
                "synchronous armor geometry resolution did not complete synchronously");

        return resolved.Result;
    }

    /// <summary>
    /// Asynchronous counterpart to <see cref="TryResolve"/>. Separate because the
    /// probes are real reads on the caller's stream, and the async decrypt path
    /// forbids blocking I/O there.
    /// </summary>
    public static ValueTask<ArmorGeometry?> TryResolveAsync(Stream source, CancellationToken cancellationToken)
        => TryResolveCore(source, async (s, p, c) =>
        {
            s.Position = p;
            return await ReadFullyAsync(s, c, cancellationToken).ConfigureAwait(false);
        });

    private static async ValueTask<ArmorGeometry?> TryResolveCore(Stream source, ReadAt readAt)
    {
        if (!source.CanSeek)
            return null;

        var origin = source.Position;

        try
        {
            return await Resolve(source, origin, readAt).ConfigureAwait(false);
        }
        catch (IOException)
        {
            return null;
        }
        finally
        {
            source.Position = origin;
        }
    }

    private delegate ValueTask<byte[]> ReadAt(Stream source, long position, int count);

    private static async ValueTask<ArmorGeometry?> Resolve(Stream source, long origin, ReadAt readAt)
    {
        var remaining = source.Length - origin;
        if (remaining <= 0)
            return null;

        // --- head: where does the body start, and how wide is a terminator? ---
        var head = await readAt(source, origin, (int)Math.Min(EdgeProbeSize, remaining)).ConfigureAwait(false);
        var headText = Encoding.ASCII.GetString(head);

        var markerIndex = headText.IndexOf(ArmorFormat.BeginMarker, StringComparison.Ordinal);
        if (markerIndex < 0)
            return null;

        // Everything before the marker must be whitespace, or this is not the
        // beginning of an armor block and the offsets would be meaningless.
        if (headText[..markerIndex].AsSpan().TrimStart(" \t\r\n").Length != 0)
            return null;

        var afterMarker = markerIndex + ArmorFormat.BeginMarker.Length;
        var terminatorWidth = TerminatorWidthAt(headText, afterMarker);
        if (terminatorWidth == 0)
            return null;

        var bodyStart = origin + afterMarker + terminatorWidth;

        // The first body line fixes the stride. A short first line means a
        // single-line body, which the tail probe resolves on its own.
        var lineStride = ArmorFormat.ColumnsPerLine + terminatorWidth;

        // --- tail: where does the body end? ---
        var tailLength = (int)Math.Min(EdgeProbeSize, source.Length - bodyStart);
        if (tailLength <= 0)
            return null;

        var tailStart = source.Length - tailLength;
        var tail = await readAt(source, tailStart, tailLength).ConfigureAwait(false);
        var tailText = Encoding.ASCII.GetString(tail);

        var endIndex = tailText.LastIndexOf(ArmorFormat.EndMarker, StringComparison.Ordinal);
        if (endIndex < 0)
            return null;

        // Only whitespace may follow the end marker.
        if (tailText[(endIndex + ArmorFormat.EndMarker.Length)..].AsSpan().Trim(" \t\r\n").Length != 0)
            return null;

        var bodyEnd = tailStart + endIndex;   // absolute offset just past the body
        var bodyBytes = bodyEnd - bodyStart;
        if (bodyBytes < 0)
            return null;

        // --- line count and the short final line ---
        var fullLines = bodyBytes / lineStride;
        var remainder = bodyBytes % lineStride;

        int lastLineChars;
        long lineCount;

        if (remainder == 0)
        {
            // Every line is full; the last one is a normal 64-column line.
            if (fullLines == 0)
                return null;

            lineCount = fullLines;
            lastLineChars = ArmorFormat.ColumnsPerLine;
        }
        else
        {
            lastLineChars = (int)remainder - terminatorWidth;
            if (lastLineChars <= 0 || lastLineChars > ArmorFormat.ColumnsPerLine)
                return null;

            lineCount = fullLines + 1;
        }

        // The final line's decoded size depends on its base64 padding, so it is read
        // rather than assumed.
        var lastLineStart = bodyStart + (lineCount - 1) * lineStride;
        var lastLine = Encoding.ASCII.GetString(await readAt(source, lastLineStart, lastLineChars).ConfigureAwait(false));

        var lastDecoded = DecodedLengthOf(lastLine);
        if (lastDecoded < 0)
            return null;

        return new ArmorGeometry
        {
            BodyStart = bodyStart,
            LineStride = lineStride,
            DecodedLength = (lineCount - 1) * ArmorFormat.BytesPerLine + lastDecoded,
        };
    }

    /// <summary>Source offset of the line holding decoded byte <paramref name="binaryOffset"/>.</summary>
    public long LineStartFor(long binaryOffset) =>
        BodyStart + binaryOffset / ArmorFormat.BytesPerLine * LineStride;

    /// <summary>How far into that line's decoded bytes the offset falls.</summary>
    public static int OffsetWithinLine(long binaryOffset) =>
        (int)(binaryOffset % ArmorFormat.BytesPerLine);

    private static int TerminatorWidthAt(string text, int index)
    {
        if (index < text.Length && text[index] == '\n')
            return 1;

        if (index + 1 < text.Length && text[index] == '\r' && text[index + 1] == '\n')
            return 2;

        return 0;
    }

    private static int DecodedLengthOf(string base64Line)
    {
        if (base64Line.Length % 4 != 0)
            return -1;

        var padding = 0;
        for (var i = base64Line.Length - 1; i >= 0 && base64Line[i] == '='; i--)
            padding++;

        return base64Line.Length / 4 * 3 - padding;
    }

    // A probe that runs off the end means this is not the layout we assumed, so the
    // EndOfStreamException these raise is an IOException that TryResolveCore catches
    // and turns into "no geometry" — the caller then falls back to forward-only.
    private static byte[] ReadFully(Stream source, int count)
    {
        var buffer = new byte[count];
        source.ReadExactly(buffer);
        return buffer;
    }

    private static async ValueTask<byte[]> ReadFullyAsync(Stream source, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        await source.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }
}
