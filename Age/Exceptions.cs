namespace Age;

/// <summary>
/// Base class for all errors thrown by this library. The hierarchy follows one
/// rule: if the input's <em>structure</em> can't be parsed, it is an
/// <see cref="AgeFormatException"/>; if the structure parsed but a
/// <em>cryptographic check</em> failed, it is an
/// <see cref="AgeAuthenticationException"/>.
/// </summary>
public class AgeException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The input's structure could not be parsed: a malformed header, stanza, or
/// ASCII armor; a parsing limit exceeded; a missing payload nonce; or an
/// invalid key, recipient, or identity string. Thrown by <c>Parse</c> methods
/// and while reading a file's header.
/// </summary>
public class AgeFormatException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeFormatException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeFormatException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The input parsed, but a cryptographic check failed: the header MAC did not
/// verify, a payload chunk failed authentication, or the STREAM sequence was
/// violated (truncated, extended, or reordered ciphertext). The file was
/// tampered with, corrupted, or an identity recovered a file key that does not
/// belong to it.
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
