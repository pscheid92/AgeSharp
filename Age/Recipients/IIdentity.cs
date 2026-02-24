using Age.Format;

namespace Age.Recipients;

public interface IIdentity
{
    /// <summary>
    /// Attempts to unwrap a file key from a stanza.
    /// Returns the file key if this identity matches, null if not.
    /// Throws if the stanza is malformed.
    /// </summary>
    byte[]? Unwrap(Stanza stanza);
}
