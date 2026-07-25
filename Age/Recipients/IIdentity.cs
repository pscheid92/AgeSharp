namespace AgeSharp;

/// <summary>
///     Recovers a file key from an age header's stanzas. Implement this to add a custom
///     identity type; most implementations override only <see cref="Unwrap(Stanza)" />.
///     <see cref="IDisposable" /> is a base so a caller holding one through the interface
///     gets the usual <c>using</c>; its default implementation does nothing.
/// </summary>
public interface IIdentity : IDisposable
{
    /// <summary>Releases any key material. Does nothing by default.</summary>
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