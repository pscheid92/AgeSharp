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
    /// Wraps the file key and reports the security labels associated with this
    /// wrapping. Encryption requires every recipient to produce the same label
    /// set (compared as an unordered set); mismatched sets are rejected — this
    /// is how post-quantum and classical recipients are kept from being mixed.
    /// </summary>
    /// <remarks>
    /// The default returns <see cref="Wrap"/>'s stanza with an empty label set.
    /// Override only when the recipient carries labels — and note labels may be
    /// dynamic (a fresh random label, or supplied by a plugin during wrapping),
    /// so they must come from the same operation that produces the stanza rather
    /// than from a separately-read property.
    /// </remarks>
    /// <param name="fileKey">The 16-byte symmetric file key that protects the payload.</param>
    /// <returns>The wrapped stanza and its label set (empty for an unlabelled recipient).</returns>
    (Stanza stanza, IReadOnlyCollection<string> labels) WrapWithLabels(ReadOnlySpan<byte> fileKey) =>
        (Wrap(fileKey), []);
}
