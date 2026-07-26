namespace AgeSharp;

/// <summary>
///     Recovers a file key from an age header's stanzas. Implement this to add a custom
///     identity type; most implementations override only <see cref="TryUnwrap(Stanza, System.Span{byte})" />.
/// </summary>
/// <remarks>
///     <see cref="IDisposable" /> is a base so that an identity held through this interface —
///     as <see cref="Age.ParseIdentity" /> and friends return it — can be <c>using</c>-scoped
///     without knowing the concrete type. The default implementation does nothing, so an
///     identity holding no secret state need not write one.
///     <para>
///         If yours does hold secret state, declare your own <c>Dispose</c> rather than relying
///         on the default. Note that a default interface method is not visible on the
///         implementing type: without your own declaration, <c>myIdentity.Dispose()</c> does not
///         compile, though <c>using</c> and a call through the interface both work.
///     </para>
/// </remarks>
public interface IIdentity : IDisposable
{
    /// <summary>Releases any key material. Does nothing unless the implementation declares its own.</summary>
    void IDisposable.Dispose()
    {
    }

    /// <summary>
    ///     Writes the file key into <paramref name="fileKey" /> and returns true, or returns
    ///     false if the stanza is addressed to a different identity.
    /// </summary>
    /// <param name="stanza">A recipient stanza from the header.</param>
    /// <param name="fileKey">
    ///     Exactly <see cref="Age.FileKeySize" /> bytes, supplied and owned by the caller.
    ///     Fill it only when returning true.
    /// </param>
    /// <remarks>
    ///     The caller supplies the buffer so that the file key need never reach the GC heap,
    ///     and so that no ownership crosses this boundary — there is nothing here for either
    ///     side to forget to clear.
    ///     <para>
    ///         Returning false must stay cheap and non-throwing: decryption tries every identity
    ///         against every stanza, so declining is the common case. Throw only when the stanza
    ///         is addressed to this identity <em>and</em> is malformed.
    ///     </para>
    /// </remarks>
    /// <exception cref="AgeFormatException">The stanza is addressed to this identity but malformed.</exception>
    bool TryUnwrap(Stanza stanza, Span<byte> fileKey);

    /// <summary>
    ///     Override only for batch protocols (plugins) that must see every stanza at once;
    ///     the default tries them one at a time.
    /// </summary>
    bool TryUnwrap(IReadOnlyList<Stanza> stanzas, Span<byte> fileKey)
    {
        foreach (var stanza in stanzas)
            if (TryUnwrap(stanza, fileKey))
                return true;

        return false;
    }
}