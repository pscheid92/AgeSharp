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

/// <summary>None of the supplied identities matched any recipient stanza in the header.</summary>
public class NoIdentityMatchException : AgeException
{
    /// <summary>Creates the exception with its fixed message.</summary>
    public NoIdentityMatchException() : base("no identity matched any recipient stanza") { }
}

/// <summary>An age plugin failed to start, misbehaved, or reported an internal error.</summary>
public class AgePluginException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgePluginException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgePluginException(string message, Exception inner) : base(message, inner) { }
}
