using System.Text;

namespace AgeSharp;

internal static class AsciiArmor
{
    private const int MaxLeadingWhitespace = 1024;

    internal static int ProbeSize => MaxLeadingWhitespace + ArmorFormat.BeginMarker.Length;

    // A push-side probe cannot wait for bytes that may never come.
    internal static int MarkerLength => ArmorFormat.BeginMarker.Length;

    internal static bool IsArmorWhitespace(byte b)
    {
        return b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';
    }

    // Lookahead rather than seeking, so detection works on pipes.
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

    private static (Stream source, bool isArmored) Result(Stream source, bool isArmored, bool requireArmored)
    {
        if (requireArmored && !isArmored)
            throw new AgeFormatException(
                "input is not ASCII-armored, but AgeDecryptOptions.RequireArmor required it to be");

        return (source, isArmored);
    }

    internal static bool StartsWithMarker(ReadOnlySpan<byte> probe)
    {
        var start = 0;
        while (start < probe.Length && IsArmorWhitespace(probe[start]))
            start++;

        var rest = probe[start..];
        var marker = Encoding.ASCII.GetBytes(ArmorFormat.BeginMarker);

        return rest.Length >= marker.Length && rest[..marker.Length].SequenceEqual(marker);
    }

    public static Stream Dearmor(Stream input, int maxArmorLineBytes = 64 * 1024)
    {
        return DearmorStream.Create(input, maxArmorLineBytes);
    }

    public static async ValueTask<Stream> DearmorAsync(Stream input, int maxArmorLineBytes,
        CancellationToken cancellationToken)
    {
        return await DearmorStream.CreateAsync(input, maxArmorLineBytes, cancellationToken).ConfigureAwait(false);
    }

    public static void Armor(Stream input, Stream output)
    {
        const int bytesPerLine = 48; // 48 bytes encode to exactly 64 base64 chars
        var readBuffer = new byte[bytesPerLine];
        Span<char> charBuffer = stackalloc char[ArmorFormat.ColumnsPerLine + 4]; // room for padding

        var writer = new StreamWriter(output, leaveOpen: true) { NewLine = "\n" };
        writer.WriteLine(ArmorFormat.BeginMarker);

        while (true)
        {
            var bytesRead = ReadChunk(input, readBuffer);

            if (bytesRead == 0)
                break;

            Convert.TryToBase64Chars(readBuffer.AsSpan(0, bytesRead), charBuffer, out var charsWritten);
            writer.Write(charBuffer[..charsWritten]);
            writer.WriteLine();
        }

        writer.WriteLine(ArmorFormat.EndMarker);
        writer.Flush();
    }

    private static int ReadChunk(Stream stream, byte[] buffer)
    {
        return stream.ReadAtLeast(buffer, buffer.Length, false);
    }

    private static ValueTask<int> ReadChunkAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        return stream.ReadAtLeastAsync(buffer, buffer.Length, false, cancellationToken);
    }
}