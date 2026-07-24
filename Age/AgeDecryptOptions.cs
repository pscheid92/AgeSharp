namespace AgeSharp;

/// <summary>
/// Options for a decrypt or header-inspection call: whether to insist the input is
/// ASCII-armored, and the resource limits applied while reading a header before any
/// bytes are authenticated. The limits exist only to stop a hostile or malformed
/// stream from exhausting memory (the header must be buffered whole to verify its MAC).
/// </summary>
/// <remarks>
/// The age specification defines no maximum header size, so these are AgeSharp's own
/// defensive limits, set far above any real file — the largest built-in stanza line
/// is ~1.5 KiB, and <see cref="MaxHeaderBytes"/> still permits well over a hundred
/// thousand recipients. Raise them only if a legitimate file ever trips one.
/// </remarks>
public sealed class AgeDecryptOptions
{
    /// <summary>
    /// If <c>true</c>, input that is not ASCII-armored is rejected with
    /// <see cref="AgeFormatException"/>.
    /// </summary>
    /// <remarks>
    /// This is a strictness opt-in, not a switch: armor is detected automatically on
    /// any stream, so the default of <c>false</c> accepts binary and armored input
    /// alike. Set it when a caller must not silently accept the wrong form — reading
    /// from a text channel that is supposed to carry armor, for instance.
    /// </remarks>
    public bool RequireArmor { get; init; }

    /// <summary>
    /// Maximum length, in bytes, of a single header line (the version line, a
    /// stanza argument line, or a stanza body line). Default: 64 KiB.
    /// </summary>
    public int MaxHeaderLineBytes { get; init; } = 64 * 1024;

    /// <summary>
    /// Maximum total length, in bytes, of the header — every line up to and
    /// including the <c>--- &lt;mac&gt;</c> line. Default: 16 MiB.
    /// </summary>
    public int MaxHeaderBytes { get; init; } = 16 * 1024 * 1024;

    /// <summary>
    /// Maximum length, in bytes, of a single ASCII-armor line. A spec-compliant
    /// armor line is at most 64 characters; the ceiling is set high so it only
    /// ever rejects a hostile unterminated line. Default: 64 KiB.
    /// </summary>
    public int MaxArmorLineBytes { get; init; } = 64 * 1024;

    internal static readonly AgeDecryptOptions Default = new();
}
