using Age.Format;

namespace Age.Recipients;

/// <summary>
/// Internal escape hatch for recipients that legitimately produce more than one stanza for a
/// single file key — share splitting, group recipients, or a key stanza plus a metadata stanza.
/// The age-plugin spec permits this and its own recipient-v1 example shows it.
/// </summary>
/// <remarks>
/// <see cref="IRecipient.Wrap"/> returns a single <see cref="Stanza"/> and is public, shipped
/// API, so it cannot be widened without breaking every existing implementer. Recipients that
/// need more implement this alongside it; <c>AgeEncrypt</c> is the only caller of <c>Wrap</c>
/// in the library, which is what lets a purely internal seam carry the whole fix.
/// </remarks>
internal interface IMultiStanzaRecipient
{
    /// <summary>Wraps the file key into one or more stanzas, all for the same file.</summary>
    IReadOnlyList<Stanza> WrapAll(ReadOnlySpan<byte> fileKey);
}
