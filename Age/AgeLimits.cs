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
/// stanza-argument length, or recipient count. The header limits are go-age's,
/// from v1.3.2 on (internal/format): an implementation that accepted more would
/// accept files the reference rejects, and the reverse. They leave ample room —
/// 2 MiB holds well over a thousand post-quantum recipients, whose stanza line
/// (an ML-KEM-768 <c>enc</c> argument) is the largest built in at ~1.5 KiB.
/// </remarks>
public static class AgeLimits
{
    /// <summary>
    /// No longer a separate limit: a header line may be as long as
    /// <see cref="MaxHeaderBytes"/> allows, as in go-age, and this now equals it.
    /// It was 64 KiB, which rejected long stanza lines go-age accepts.
    /// </summary>
    [Obsolete("A header line is limited only by MaxHeaderBytes, as in go-age.")]
    public const int MaxHeaderLineBytes = MaxHeaderBytes;

    /// <summary>
    /// Maximum total length, in bytes, of the header — every line up to and
    /// including the <c>--- &lt;mac&gt;</c> line. 2 MiB, as in go-age.
    /// </summary>
    public const int MaxHeaderBytes = 2 * 1024 * 1024;

    /// <summary>Maximum number of recipient stanzas in a header. 1024, as in go-age.</summary>
    public const int MaxRecipientStanzas = 1024;

    /// <summary>Maximum number of arguments on one stanza line. 128, as in go-age.</summary>
    public const int MaxStanzaArguments = 128;

    /// <summary>
    /// Maximum length, in bytes, of a single ASCII-armor line. A spec-compliant
    /// armor line is at most 64 characters; the ceiling is set high so it only
    /// ever rejects a hostile unterminated line, never legitimate input.
    /// Default: 64 KiB.
    /// </summary>
    public const int MaxArmorLineBytes = 64 * 1024;

    // Whitespace is allowed around the armor, before BEGIN and after END; unbounded, a file of
    // nothing but newlines is read to its end. The same allowance at both ends, as go-age has.
    internal const int MaxArmorWhitespaceBytes = 1024;
}
