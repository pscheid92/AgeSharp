using Age.Format;

namespace Age.Recipients;

/// <summary>
/// Wraps an age file key into a stanza that a matching <see cref="IIdentity"/>
/// can later unwrap. Implement this interface to add a custom recipient type;
/// the stanza produced here becomes part of the age header's recipient list.
/// </summary>
public interface IRecipient
{
    /// <summary>
    /// Wraps the file key into a stanza. Called once per encryption.
    /// </summary>
    /// <param name="fileKey">The 16-byte symmetric file key that protects the payload.</param>
    /// <returns>
    /// A <see cref="Stanza"/> whose <c>Type</c> identifies the recipient kind
    /// (e.g. "X25519", "scrypt", a custom type) and whose <c>Args</c> and
    /// <c>Body</c> carry any recipient-specific data needed to unwrap.
    /// </returns>
    Stanza Wrap(ReadOnlySpan<byte> fileKey);

    /// <summary>
    /// Optional security label. Recipients with different labels cannot be
    /// mixed in a single encryption (e.g. to prevent mixing post-quantum and
    /// classical recipients). <c>null</c> means "no label."
    /// </summary>
    string? Label => null;
}
