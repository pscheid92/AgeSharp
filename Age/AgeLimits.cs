namespace Age;

/// <summary>
/// Resource limits applied while reading an age file's header and ASCII armor,
/// before any bytes are authenticated. They exist only to stop a hostile or
/// malformed stream from exhausting memory: the header must be buffered whole to
/// verify its MAC, so without a ceiling an unterminated or endlessly repeated
/// line could be read until the process runs out of memory.
/// </summary>
/// <remarks>
/// The age specification (C2SP <c>age.md</c>) defines no maximum header size,
/// stanza-argument length, or recipient count — a stanza argument is
/// <c>1*VCHAR</c> with no upper bound — so these are AgeSharp's own defensive
/// limits, not a spec requirement. They are set far above any real age file:
/// the largest built-in stanza line (an ML-KEM-768 <c>enc</c> argument) is
/// ~1.5 KiB, and <see cref="MaxHeaderBytes"/> still permits well over a hundred
/// thousand recipients. If a legitimate file ever trips one of these, that is
/// the signal to make them configurable rather than to remove them.
/// </remarks>
public static class AgeLimits
{
    /// <summary>
    /// Maximum length, in bytes, of a single header line — the version line, a
    /// stanza argument line, or a stanza body line. Default: 64 KiB.
    /// </summary>
    public const int MaxHeaderLineBytes = 64 * 1024;

    /// <summary>
    /// Maximum total length, in bytes, of the header — every line up to and
    /// including the <c>--- &lt;mac&gt;</c> line. Bounds a header padded out with
    /// a huge number of small stanzas. Default: 16 MiB.
    /// </summary>
    public const int MaxHeaderBytes = 16 * 1024 * 1024;

    /// <summary>
    /// Maximum length, in bytes, of a single ASCII-armor line. A spec-compliant
    /// armor line is at most 64 characters; the ceiling is set high so it only
    /// ever rejects a hostile unterminated line, never legitimate input.
    /// Default: 64 KiB.
    /// </summary>
    public const int MaxArmorLineBytes = 64 * 1024;

    // Maximum whitespace, in bytes, permitted before the armor BEGIN marker. The spec allows
    // leading whitespace, but without a bound a file consisting entirely of newlines is read to
    // its end before the header is looked for. Matches go-age's limit.
    //
    // Deliberately internal: a patch release should not grow the public surface, and nothing
    // outside the assembly needs it.
    internal const int MaxLeadingWhitespaceBytes = 1024;
}
