using Age.Format;

namespace Age.Recipients;

/// <summary>
/// Attempts to recover a file key from stanzas in an age header. Implement
/// this to add a custom identity type. Most implementations override only
/// <see cref="Unwrap(Stanza)"/>; the list overload has a default implementation
/// that iterates through stanzas one at a time.
/// </summary>
public interface IIdentity
{
    /// <summary>
    /// Attempts to unwrap a file key from a single stanza. Required override.
    /// </summary>
    /// <param name="stanza">One recipient stanza from the age header.</param>
    /// <returns>
    /// The 16-byte file key if this identity can unwrap the stanza;
    /// <c>null</c> if the stanza is addressed to a different identity.
    /// </returns>
    /// <exception cref="AgeHeaderException">The stanza is malformed.</exception>
    byte[]? Unwrap(Stanza stanza);

    /// <summary>
    /// Attempts to unwrap a file key from any of the provided stanzas.
    /// The default implementation iterates stanzas one at a time, returning
    /// the first successful unwrap. Override for batch-based identity protocols
    /// (e.g. plugin identities) that need to see the full stanza list at once.
    /// </summary>
    byte[]? Unwrap(IReadOnlyList<Stanza> stanzas) =>
        stanzas.Select(Unwrap).OfType<byte[]>().FirstOrDefault();
}