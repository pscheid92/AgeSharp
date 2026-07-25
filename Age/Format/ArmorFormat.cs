namespace AgeSharp;

/// <summary>
/// The fixed facts of the ASCII armor format, in one place.
/// </summary>
/// <remarks>
/// These were previously redeclared in each armor type, which is a quiet hazard rather
/// than mere repetition: <see cref="ArmorGeometry"/> translates a binary offset to a
/// text position using arithmetic that is only valid while its idea of the line width
/// matches what <see cref="ArmorDecoder"/> accepts and what the writers emit. Sharing
/// the constants is what stops those drifting apart under a later edit — a mismatch
/// would compute offsets that land mid-line, and armor is exactly the layer where that
/// fails as an authentication error rather than anything legible.
/// </remarks>
internal static class ArmorFormat
{
    public const string BeginMarker = "-----BEGIN AGE ENCRYPTED FILE-----";
    public const string EndMarker = "-----END AGE ENCRYPTED FILE-----";

    /// <summary>Base64 characters in a full body line.</summary>
    public const int ColumnsPerLine = 64;

    /// <summary>Bytes a full body line decodes to — 64 base64 characters carry 48 bytes.</summary>
    public const int BytesPerLine = 48;
}
