using Age.Format;

namespace Age.Recipients;

/// <summary>
/// Wraps an age file key into one or more stanzas that a matching <see cref="IIdentity"/> can
/// later unwrap. Implement this to add a custom recipient type; the stanzas produced here become
/// part of the age header's recipient list.
/// </summary>
public interface IRecipient
{
    /// <summary>Wraps the file key. Called once per encryption.</summary>
    /// <param name="fileKey">The 16-byte file key that protects the payload.</param>
    /// <returns>
    /// One or more stanzas, each with a <c>Type</c> naming the recipient kind and the <c>Args</c>
    /// and <c>Body</c> needed to unwrap it. Returning several is how one recipient stands for a
    /// group or proxies for something else; an age plugin may produce several. Most
    /// implementations return exactly one: <c>[stanza]</c>. An empty list is refused.
    /// </returns>
    IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey);
}
