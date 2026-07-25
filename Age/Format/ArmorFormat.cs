namespace AgeSharp;

// One source of truth for the format's fixed facts. ArmorGeometry's offset arithmetic is
// only valid while its idea of the line width matches what ArmorDecoder accepts and the
// writers emit, and a mismatch would compute offsets landing mid-line.
internal static class ArmorFormat
{
    public const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    public const string EndMarker = "-----END AGE ENCRYPTED FILE-----";

    public const int ColumnsPerLine = 64;

    // 64 base64 characters carry 48 bytes.
    public const int BytesPerLine = 48;
}