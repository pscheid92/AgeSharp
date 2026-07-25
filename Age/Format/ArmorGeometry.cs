using System.Text;

namespace AgeSharp;

// Armor is position-computable: binary byte i lives on line i/48 at offset i%48, so the
// layout resolves from one probe at each end rather than a scan. A miscomputed offset
// fails authentication rather than decoding to something plausible.
internal sealed class ArmorGeometry
{
    // Distinct from AsciiArmor's detection probe, which is sized differently.
    private const int EdgeProbeSize = 8192;

    public long BodyStart { get; private init; }

    public int LineStride { get; private init; }

    public long DecodedLength { get; private init; }

    public static ArmorGeometry? TryResolve(Stream source)
    {
        var resolved = TryResolveCore(source, static (s, p, c) =>
        {
            s.Position = p;
            return ValueTask.FromResult(ReadFully(s, c));
        });

        // Guarded rather than assumed: a future async step here would otherwise block silently.
        if (!resolved.IsCompleted)
            throw new InvalidOperationException(
                "synchronous armor geometry resolution did not complete synchronously");

        return resolved.Result;
    }

    public static ValueTask<ArmorGeometry?> TryResolveAsync(Stream source, CancellationToken cancellationToken)
    {
        return TryResolveCore(source, async (s, p, c) =>
        {
            s.Position = p;
            return await ReadFullyAsync(s, c, cancellationToken).ConfigureAwait(false);
        });
    }

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

    private static async ValueTask<ArmorGeometry?> Resolve(Stream source, long origin, ReadAt readAt)
    {
        var remaining = source.Length - origin;
        if (remaining <= 0)
            return null;

        var head = await readAt(source, origin, (int)Math.Min(EdgeProbeSize, remaining)).ConfigureAwait(false);
        var headText = Encoding.ASCII.GetString(head);

        var markerIndex = headText.IndexOf(ArmorFormat.BeginMarker, StringComparison.Ordinal);
        if (markerIndex < 0)
            return null;

        if (headText[..markerIndex].AsSpan().TrimStart(" \t\r\n").Length != 0)
            return null;

        var afterMarker = markerIndex + ArmorFormat.BeginMarker.Length;
        var terminatorWidth = TerminatorWidthAt(headText, afterMarker);
        if (terminatorWidth == 0)
            return null;

        var bodyStart = origin + afterMarker + terminatorWidth;

        var lineStride = ArmorFormat.ColumnsPerLine + terminatorWidth;

        var tailLength = (int)Math.Min(EdgeProbeSize, source.Length - bodyStart);
        if (tailLength <= 0)
            return null;

        var tailStart = source.Length - tailLength;
        var tail = await readAt(source, tailStart, tailLength).ConfigureAwait(false);
        var tailText = Encoding.ASCII.GetString(tail);

        var endIndex = tailText.LastIndexOf(ArmorFormat.EndMarker, StringComparison.Ordinal);
        if (endIndex < 0)
            return null;

        if (tailText[(endIndex + ArmorFormat.EndMarker.Length)..].AsSpan().Trim(" \t\r\n").Length != 0)
            return null;

        var bodyEnd = tailStart + endIndex; // absolute offset just past the body
        var bodyBytes = bodyEnd - bodyStart;
        if (bodyBytes < 0)
            return null;

        var fullLines = bodyBytes / lineStride;
        var remainder = bodyBytes % lineStride;

        int lastLineChars;
        long lineCount;

        if (remainder == 0)
        {
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

        var lastLineStart = bodyStart + (lineCount - 1) * lineStride;
        var lastLine =
            Encoding.ASCII.GetString(await readAt(source, lastLineStart, lastLineChars).ConfigureAwait(false));

        var lastDecoded = DecodedLengthOf(lastLine);
        if (lastDecoded < 0)
            return null;

        return new ArmorGeometry
        {
            BodyStart = bodyStart,
            LineStride = lineStride,
            DecodedLength = (lineCount - 1) * ArmorFormat.BytesPerLine + lastDecoded
        };
    }

    public long LineStartFor(long binaryOffset)
    {
        return BodyStart + binaryOffset / ArmorFormat.BytesPerLine * LineStride;
    }

    public static int OffsetWithinLine(long binaryOffset)
    {
        return (int)(binaryOffset % ArmorFormat.BytesPerLine);
    }

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

    private delegate ValueTask<byte[]> ReadAt(Stream source, long position, int count);
}