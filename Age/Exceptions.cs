namespace Age;

/// <summary>
/// Base class for all age-specific errors thrown by this library. Parse methods
/// on key types (e.g. <see cref="Recipients.X25519Identity.Parse"/>) throw
/// <see cref="FormatException"/> instead, matching BCL parsing conventions.
/// </summary>
public class AgeException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>The age header is malformed or violates a format rule.</summary>
public class AgeHeaderException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeHeaderException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgeHeaderException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The header MAC failed verification: the header was modified after encryption,
/// or an identity recovered a file key that does not belong to this file.
/// </summary>
public class AgeHmacException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeHmacException(string message) : base(message) { }
}

/// <summary>The payload is malformed, truncated, or failed chunk authentication.</summary>
public class AgePayloadException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgePayloadException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public AgePayloadException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>The ASCII armor wrapping is malformed.</summary>
public class AgeArmorException : AgeException
{
    /// <summary>Creates the exception with a message.</summary>
    public AgeArmorException(string message) : base(message) { }
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
