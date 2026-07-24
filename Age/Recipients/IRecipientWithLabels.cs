
namespace AgeSharp;

/// <summary>
/// An <see cref="IRecipient"/> that also produces security labels when it wraps
/// the file key. Encryption requires every recipient to produce the same label
/// set (compared as an unordered set); a mismatch is rejected — this is how
/// post-quantum and classical recipients are kept from being mixed. Recipients
/// without labels implement only <see cref="IRecipient"/> and are treated as
/// having an empty set.
/// </summary>
/// <remarks>
/// Labels come out of the wrap operation rather than a separately-read property
/// because they can be dynamic: a fresh random label (to force a recipient to be
/// used alone), or a label supplied by a plugin during the wrap exchange. Mirrors
/// the reference implementation's <c>RecipientWithLabels</c>.
/// </remarks>
public interface IRecipientWithLabels : IRecipient
{
    /// <summary>
    /// Wraps the file key and returns the stanza together with the label set for
    /// this wrapping.
    /// </summary>
    /// <param name="fileKey">The 16-byte symmetric file key that protects the payload.</param>
    /// <returns>The wrapped stanza and its (non-empty) label set.</returns>
    (Stanza stanza, IReadOnlyCollection<string> labels) WrapWithLabels(ReadOnlySpan<byte> fileKey);
}
