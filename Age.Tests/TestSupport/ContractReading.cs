using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Reads the recipient and identity contracts the way most tests need them: one stanza out of a
/// recipient that produces exactly one, and the file key, or null, out of an identity.
/// </summary>
internal static class ContractReading
{
    /// <summary>The single stanza a recipient produces; fails the test if it produces more or none.</summary>
    public static Stanza WrapSingle(this IRecipient recipient, ReadOnlySpan<byte> fileKey) =>
        Assert.Single(recipient.Wrap(fileKey));

    /// <summary>The file key the identity unwraps from the stanza, or null if it declines.</summary>
    public static byte[]? UnwrapOrNull(this IIdentity identity, Stanza stanza)
    {
        var fileKey = new byte[16];
        return identity.TryUnwrap(stanza, fileKey) ? fileKey : null;
    }

    /// <summary>The file key the identity unwraps from any of the stanzas, or null if it declines.</summary>
    public static byte[]? UnwrapOrNull(this IIdentity identity, IReadOnlyList<Stanza> stanzas)
    {
        var fileKey = new byte[16];
        return identity.TryUnwrap(stanzas, fileKey) ? fileKey : null;
    }
}
