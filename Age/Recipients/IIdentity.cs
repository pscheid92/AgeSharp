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

    /// <summary>
    /// Attempts to unwrap a file key from any of the provided stanzas.
    /// Default implementation iterates one at a time; plugin identities override for batching.
    /// </summary>
    byte[]? Unwrap(IReadOnlyList<Stanza> stanzas)
    {
        foreach (var stanza in stanzas)
        {
            var fileKey = Unwrap(stanza);
            if (fileKey is not null) return fileKey;
        }
        return null;
    }
}
