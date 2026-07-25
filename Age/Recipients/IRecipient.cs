namespace AgeSharp;

/// <summary>
///     Wraps an age file key into one or more stanzas that a matching
///     <see cref="IIdentity" /> can later unwrap. Implement this to add a custom recipient
///     type; the stanzas produced here become part of the age header's recipient list.
/// </summary>
public interface IRecipient
{
    /// <summary>
    ///     Wraps the file key. Called once per encryption.
    /// </summary>
    /// <returns>
    ///     One or more stanzas, each with a <c>Type</c> identifying the recipient kind and
    ///     the <c>Args</c> and <c>Body</c> needed to unwrap it. Returning several is how a
    ///     single recipient can stand for a group, offer multiple formats, or proxy for
    ///     something else — an age plugin may legitimately produce more than one. Most
    ///     implementations return exactly one: <c>[stanza]</c>.
    /// </returns>
    IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey);
}
