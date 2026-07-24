namespace AgeSharp;

/// <summary>
/// Options for an encrypt or decrypt call: whether to ASCII-armor the output,
/// and the resource limits applied while reading a header before any bytes are
/// authenticated. The limits exist only to stop a hostile or malformed stream
/// from exhausting memory (the header must be buffered whole to verify its MAC).
/// </summary>
/// <remarks>
/// The age specification defines no maximum header size, so these are AgeSharp's
/// own defensive limits, set far above any real file — the largest built-in
/// stanza line is ~1.5 KiB, and <see cref="MaxHeaderBytes"/> still permits well
/// over a hundred thousand recipients. Raise them only if a legitimate file ever
/// trips one.
/// </remarks>
public sealed class AgeOptions
{
    /// <summary>
    /// If <c>true</c>, encryption produces a PEM-like ASCII-armored text block
    /// instead of raw binary. Ignored on decryption (armor is auto-detected).
    /// </summary>
    public bool Armor { get; init; }

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

    internal static readonly AgeOptions Default = new();
}
