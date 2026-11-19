namespace Age.Recipients;

/// <summary>
/// An <see cref="IRecipient"/> that also produces security labels. Every recipient in a file
/// must produce the same set (compared unordered and case-sensitively), which is what stops
/// post-quantum and classical recipients being mixed; a recipient without labels has an empty
/// set. Labels come out of the wrap rather than a property because they can be dynamic, such as
/// a fresh random label or one a plugin supplies.
/// </summary>
public interface IRecipientWithLabels : IRecipient
{
    /// <summary>Wraps the file key, returning the stanzas together with this wrapping's labels.</summary>
    LabelledStanzas WrapWithLabels(ReadOnlySpan<byte> fileKey);
}
