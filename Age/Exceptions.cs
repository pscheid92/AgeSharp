namespace AgeSharp;

/// <summary>
///     Base class for every error this library throws. One rule splits the hierarchy: an
///     unparseable <em>structure</em> is an <see cref="AgeFormatException" />, a failed
///     <em>cryptographic check</em> is an <see cref="AgeAuthenticationException" />.
/// </summary>
/// <remarks>
///     Thrown directly, not only inherited from, for failures the caller caused but which are
///     only discovered mid-operation: recipients with mismatched labels, or an scrypt stanza
///     alongside others. Those are not <see cref="ArgumentException" />s — the offending thing
///     is a combination that only appears once each recipient has wrapped, and a custom
///     recipient can emit an scrypt stanza without looking like a passphrase beforehand.
///     <para>
///         Deliberately not sealed: a custom <see cref="IRecipient" /> or <see cref="IIdentity" />
///         should derive its own failures from this, so that catching
///         <see cref="AgeException" /> keeps catching everything.
///     </para>
/// </remarks>
public class AgeException : Exception
{
    /// <inheritdoc />
    public AgeException(string message) : base(message)
    {
    }

    /// <inheritdoc />
    public AgeException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>
///     The input's structure could not be parsed: malformed header, stanza, or armor; a
///     parsing limit exceeded; or an invalid key, recipient, or identity string.
/// </summary>
public class AgeFormatException : AgeException
{
    /// <inheritdoc />
    public AgeFormatException(string message) : base(message)
    {
    }

    /// <inheritdoc />
    public AgeFormatException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>
///     The input parsed, but a cryptographic check failed: the header MAC did not
///     verify, a payload chunk failed authentication, or the STREAM sequence was
///     violated (truncated, extended, or reordered ciphertext). The file was
///     tampered with, corrupted, or an identity recovered a file key that does not
///     belong to it.
/// </summary>
public class AgeAuthenticationException : AgeException
{
    /// <inheritdoc />
    public AgeAuthenticationException(string message) : base(message)
    {
    }

    /// <inheritdoc />
    public AgeAuthenticationException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>None of the supplied identities matched any recipient stanza in the header.</summary>
public class NoIdentityMatchException : AgeException
{
    /// <summary>Creates the exception with its fixed message.</summary>
    public NoIdentityMatchException() : base("no identity matched any recipient stanza")
    {
    }
}

/// <summary>An age plugin failed to start, misbehaved, or reported an internal error.</summary>
public class AgePluginException : AgeException
{
    /// <inheritdoc />
    public AgePluginException(string message) : base(message)
    {
    }

    /// <inheritdoc />
    public AgePluginException(string message, Exception inner) : base(message, inner)
    {
    }
}