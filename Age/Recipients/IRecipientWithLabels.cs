namespace AgeSharp;

/// <summary>
///     An <see cref="IRecipient" /> that also produces security labels. Every recipient in
///     a file must produce the same set (compared unordered), which is what stops
///     post-quantum and classical recipients being mixed; recipients without labels are
///     treated as having an empty set. Labels come out of the wrap rather than a property
///     because they can be dynamic — a fresh random label, or one a plugin supplies.
/// </summary>
public interface IRecipientWithLabels : IRecipient
{
    /// <summary>Wraps the file key, returning the stanzas and this wrapping's label set.</summary>
    (IReadOnlyList<Stanza> stanzas, IReadOnlyCollection<string> labels) WrapWithLabels(ReadOnlySpan<byte> fileKey);
}