namespace AgeSharp;

/// <summary>
///     Recovers a file key from an age header's stanzas. Implement this to add a custom
///     identity type; most implementations override only <see cref="Unwrap(Stanza)" />.
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
    ///     The 16-byte file key, or <c>null</c> if the stanza is addressed to a different
    ///     identity. "Not mine" must be null rather than an exception: decryption tries every
    ///     identity against every stanza, so declining is the common case.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza is malformed.</exception>
    byte[]? Unwrap(Stanza stanza);

    /// <summary>
    ///     Override only for batch protocols (plugins) that must see every stanza at once;
    ///     the default tries them one at a time.
    /// </summary>
    byte[]? Unwrap(IReadOnlyList<Stanza> stanzas)
    {
        return stanzas.Select(Unwrap).OfType<byte[]>().FirstOrDefault();
    }
}