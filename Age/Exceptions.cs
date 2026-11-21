namespace AgeSharp;

/// <summary>
/// Base class for all age-specific errors thrown by this library. One rule splits what reading a
/// file can fail with: a structure that does not parse is an <see cref="AgeFormatException"/>, a
/// cryptographic check that fails is an <see cref="AgeAuthenticationException"/>.
/// </summary>
/// <remarks>
/// <para>
/// Thrown directly for failures the caller caused that only show mid-operation: recipients with
/// different security labels, or a passphrase among other recipients' stanzas.
/// </para>
/// <para>
/// Parse methods on key types (e.g. <see cref="X25519Identity.Parse"/>) throw
/// <see cref="FormatException"/> instead, matching BCL parsing conventions. Not sealed: a custom
/// recipient or identity can derive its own failures from it, so catching
/// <see cref="AgeException"/> still catches everything.
/// </para>
/// </remarks>
public class AgeException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The input's structure could not be parsed: a malformed header, stanza or armor, a payload
/// nonce cut short, or a parsing limit exceeded (see <see cref="AgeDecryptOptions"/>).
/// </summary>
/// <remarks>
/// Parsing a key, recipient or identity from text throws the BCL <see cref="FormatException"/>
/// instead, as .NET's own <c>Parse</c> methods do.
/// </remarks>
public class AgeFormatException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeFormatException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeFormatException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The input parsed, but a cryptographic check failed: the header MAC did not verify, a payload
/// chunk failed authentication, or the chunks are not the sequence they were encrypted as
/// (truncated, extended, reordered). The file was tampered with or damaged, or an identity
/// recovered a file key that is not this file's.
/// </summary>
public class AgeAuthenticationException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeAuthenticationException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeAuthenticationException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// None of the identities opened any of the file's stanzas. Says what the file holds and why each
/// identity, in the order they were tried, did not open it.
/// </summary>
/// <remarks>
/// It holds only text: an exception gets logged, and outlives the identities it names, so it
/// keeps neither them nor anything secret of theirs.
/// </remarks>
public class NoIdentityMatchException : AgeException
{
    /// <summary>A no-match, with the file's stanza types and why each identity did not match.</summary>
    /// <param name="stanzaTypes">The type of each stanza in the file, in order, as go-age reports them.</param>
    /// <param name="mismatches">Why each identity did not match, in the order they were tried.</param>
    public NoIdentityMatchException(IReadOnlyList<string> stanzaTypes, IReadOnlyList<IdentityMismatch> mismatches)
        : base(Describe(stanzaTypes, mismatches))
    {
        StanzaTypes = stanzaTypes;
        Mismatches = mismatches;
    }

    /// <summary>The type of each stanza in the file's header, in order.</summary>
    public IReadOnlyList<string> StanzaTypes { get; }

    /// <summary>Why each identity did not match, in the order they were tried.</summary>
    public IReadOnlyList<IdentityMismatch> Mismatches { get; }

    private static string Describe(IReadOnlyList<string> stanzaTypes, IReadOnlyList<IdentityMismatch> mismatches)
    {
        ArgumentNullException.ThrowIfNull(stanzaTypes);
        ArgumentNullException.ThrowIfNull(mismatches);

        var has = stanzaTypes.Count == 0 ? "no stanzas" : string.Join(", ", stanzaTypes.Distinct(StringComparer.Ordinal));
        var why = mismatches.Select(m => $"{m.Identity}: {m.Explanation}");

        return string.Join("; ", ["no identity matched any recipient stanza", $"the file has {has}", .. why]);
    }
}

/// <summary>Why an identity did not open a file.</summary>
public enum IdentityMismatchReason
{
    /// <summary>The file has no stanza of the type the identity opens.</summary>
    NoStanzaOfItsType,

    /// <summary>The file has stanzas of the identity's type, but none for it: another key, or another passphrase.</summary>
    NoStanzaForIt,

    /// <summary>The identity opened none of the stanzas. A custom or plugin identity, which does not say which type it opens.</summary>
    DidNotMatch,
}

/// <summary>One identity that did not open a file, and why.</summary>
/// <param name="Identity">Which identity: its type, and the start of its recipient where it has one. Nothing secret.</param>
/// <param name="Reason">Why it did not match.</param>
/// <param name="StanzaType">The stanza type the identity opens, where it says.</param>
public sealed record IdentityMismatch(string Identity, IdentityMismatchReason Reason, string? StanzaType)
{
    /// <summary>The reason in words.</summary>
    public string Explanation => Reason switch
    {
        IdentityMismatchReason.NoStanzaOfItsType => $"the file has no {StanzaType} stanza",
        IdentityMismatchReason.NoStanzaForIt => $"the file's {StanzaType} stanzas are not for it",
        _ => "it opened none of the stanzas",
    };
}

/// <summary>An age plugin failed to start, misbehaved, or reported an internal error.</summary>
public class AgePluginException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgePluginException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgePluginException(string message, Exception inner) : base(message, inner) { }
}
