using Age.Format;

namespace Age.Recipients;

/// <summary>
/// Recovers a file key from an age header's stanzas. Implement this to add a custom identity
/// type; most implementations write only <see cref="TryUnwrap(Stanza, Span{byte})"/>.
/// </summary>
/// <remarks>
/// <see cref="IDisposable"/> is a base so that an identity held through this interface, as
/// parsing returns it, can be <c>using</c>-scoped without knowing its type. The default
/// <c>Dispose</c> does nothing, so an identity holding no secret need not write one.
/// <para>
/// One that does hold a secret should declare its own <c>Dispose</c>. A default interface
/// method is not visible on the implementing type: without your own, <c>myIdentity.Dispose()</c>
/// does not compile, though <c>using</c> and a call through the interface both work.
/// </para>
/// </remarks>
public interface IIdentity : IDisposable
{
    /// <summary>Releases any key material. Does nothing unless the implementation declares its own.</summary>
    void IDisposable.Dispose()
    {
    }

    /// <summary>
    /// Writes the file key into <paramref name="fileKey"/> and returns true, or returns false if
    /// the stanza is addressed to a different identity.
    /// </summary>
    /// <param name="stanza">A recipient stanza from the header.</param>
    /// <param name="fileKey">
    /// Exactly 16 bytes, supplied and owned by the caller. Fill it only when returning true.
    /// </param>
    /// <remarks>
    /// The caller supplies the buffer, so no ownership crosses this boundary and neither side
    /// has a copy of the key to forget to clear.
    /// <para>
    /// Returning false must stay cheap and must not throw: decryption tries every identity
    /// against every stanza, so declining is the common case. Throw only when the stanza is
    /// addressed to this identity and is malformed.
    /// </para>
    /// </remarks>
    /// <exception cref="AgeHeaderException">The stanza is addressed to this identity but is malformed.</exception>
    bool TryUnwrap(Stanza stanza, Span<byte> fileKey);

    /// <summary>
    /// Tries each stanza in turn. Override only for a protocol that must see every stanza at
    /// once, as a plugin does.
    /// </summary>
    bool TryUnwrap(IReadOnlyList<Stanza> stanzas, Span<byte> fileKey)
    {
        foreach (var stanza in stanzas)
        {
            if (TryUnwrap(stanza, fileKey))
                return true;
        }

        return false;
    }
}
