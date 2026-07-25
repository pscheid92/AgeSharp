using System.Buffers.Text;
using System.Text;

namespace AgeSharp;

// The encode counterpart to ArmorDecoder: sans-I/O, so the pull-side ArmorStream and the
// push-side ArmorWriterStream share one definition of what armor looks like on the wire.
internal static class ArmorEncoder
{
    public const int MaxEncodedPerLine = ArmorFormat.ColumnsPerLine + 1;

    public static readonly byte[] BeginMarkerLine = Encoding.ASCII.GetBytes(ArmorFormat.BeginMarker + "\n");
    public static readonly byte[] EndMarkerLine = Encoding.ASCII.GetBytes(ArmorFormat.EndMarker + "\n");

    // Encodes up to ArmorFormat.BytesPerLine source bytes as one terminated body line,
    // returning its length. A short source yields the final, short line.
    public static int EncodeLine(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Base64.EncodeToUtf8(source, destination, out _, out var written);
        destination[written] = (byte)'\n';
        return written + 1;
    }
}
