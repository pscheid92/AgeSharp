using System.Text;

namespace AgeSharp;

internal static class AsciiArmor
{
    private const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string EndMarker = "-----END AGE ENCRYPTED FILE-----";
    private const int ColumnsPerLine = 64;

    /// <summary>
    /// Maximum leading whitespace tolerated before the begin marker. The spec allows
    /// leading whitespace but sets no bound; this matches the age CLI's own limit and
    /// keeps the detection probe a fixed size, so detection needs no seeking.
    /// </summary>
    private const int MaxLeadingWhitespace = 1024;

    private static int ProbeSize => MaxLeadingWhitespace + BeginMarker.Length;

    /// <summary>
    /// Decides whether <paramref name="input"/> is ASCII-armored, returning the stream
    /// to read from afterwards. Detection uses lookahead rather than seeking, so it
    /// works on pipes and sockets: a seekable source is probed and rewound (keeping its
    /// seekability intact for the binary path), and any other source is wrapped in a
    /// <see cref="PeekableStream"/> that replays the probed bytes.
    /// </summary>
    public static (Stream source, bool isArmored) Detect(Stream input, bool requireArmored = false)
    {
        var probe = new byte[ProbeSize];

        if (input.CanSeek)
        {
            var pos = input.Position;
            var read = ReadChunk(input, probe);
            input.Position = pos;
            return Result(input, StartsWithMarker(probe.AsSpan(0, read)), requireArmored);
        }

        var peekable = new PeekableStream(input);
        var peeked = peekable.Peek(probe);
        return Result(peekable, StartsWithMarker(probe.AsSpan(0, peeked)), requireArmored);
    }

    /// <summary>Asynchronous, purity-safe counterpart to <see cref="Detect"/>.</summary>
    public static async ValueTask<(Stream source, bool isArmored)> DetectAsync(Stream input, bool requireArmored,
                                                                                CancellationToken cancellationToken)
    {
        var probe = new byte[ProbeSize];

        if (input.CanSeek)
        {
            var pos = input.Position;
            var read = await ReadChunkAsync(input, probe, cancellationToken).ConfigureAwait(false);
            input.Position = pos;
            return Result(input, StartsWithMarker(probe.AsSpan(0, read)), requireArmored);
        }

        var peekable = new PeekableStream(input);
        var peeked = await peekable.PeekAsync(probe, cancellationToken).ConfigureAwait(false);
        return Result(peekable, StartsWithMarker(probe.AsSpan(0, peeked)), requireArmored);
    }

    // Enforcing the strictness opt-in here keeps it in one place: the decrypt, async
    // decrypt, and header-inspection paths all detect through these two methods.
    private static (Stream source, bool isArmored) Result(Stream source, bool isArmored, bool requireArmored)
    {
        if (requireArmored && !isArmored)
            throw new AgeFormatException("input is not ASCII-armored, but AgeDecryptOptions.RequireArmor required it to be");

        return (source, isArmored);
    }

    // Pure: does the probe begin (after allowed whitespace) with the armor marker?
    private static bool StartsWithMarker(ReadOnlySpan<byte> probe)
    {
        var start = 0;
        while (start < probe.Length && probe[start] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            start++;

        // All whitespace within the probe means either an empty stream or more
        // leading whitespace than we accept — neither is armor we can read.
        var rest = probe[start..];
        var marker = Encoding.ASCII.GetBytes(BeginMarker);

        return rest.Length >= marker.Length && rest[..marker.Length].SequenceEqual(marker);
    }

    /// <summary>
    /// Wraps an armored source in a stream that yields the decoded binary bytes.
    /// The returned stream never disposes <paramref name="input"/> — ownership of the
    /// source stays with the caller, as everywhere else in the library.
    /// </summary>
    public static Stream Dearmor(Stream input, int maxArmorLineBytes = 64 * 1024)
        => new DearmorStream(input, maxArmorLineBytes);

    public static void Armor(Stream input, Stream output)
    {
        const int bytesPerLine = 48; // 48 bytes encode to exactly 64 base64 chars
        var readBuffer = new byte[bytesPerLine];
        Span<char> charBuffer = stackalloc char[ColumnsPerLine + 4]; // room for padding

        var writer = new StreamWriter(output, leaveOpen: true) { NewLine = "\n" };
        writer.WriteLine(BeginMarker);

        while (true)
        {
            var bytesRead = ReadChunk(input, readBuffer);

            if (bytesRead == 0)
                break;

            Convert.TryToBase64Chars(readBuffer.AsSpan(0, bytesRead), charBuffer, out var charsWritten);
            writer.Write(charBuffer[..charsWritten]);
            writer.WriteLine();
        }

        writer.WriteLine(EndMarker);
        writer.Flush();
    }

    private static int ReadChunk(Stream stream, byte[] buffer)
    {
        var total = 0;

        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }

    private static async ValueTask<int> ReadChunkAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var total = 0;

        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }
}