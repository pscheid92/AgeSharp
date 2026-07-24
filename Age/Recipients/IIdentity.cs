
namespace AgeSharp;

/// <summary>
/// Attempts to recover a file key from stanzas in an age header. Implement
/// this to add a custom identity type. Most implementations override only
/// <see cref="Unwrap(Stanza)"/>; the list overload has a default implementation
/// that iterates through stanzas one at a time.
/// </summary>
/// <remarks>
/// Identities extend <see cref="IDisposable"/> so that key material can be zeroed
/// deterministically — and, more importantly, so callers holding an identity through
/// the interface (as <see cref="Age.ParseIdentity"/> and friends return it) get the
/// usual <c>using</c> affordance without having to know the concrete type. A default
/// no-op <see cref="IDisposable.Dispose"/> is supplied, so implementations that hold
/// no unmanaged or secret state need not write one.
/// </remarks>
public interface IIdentity : IDisposable
{
    /// <summary>
    /// Releases any key material held by this identity. The default implementation
    /// does nothing, for identities that hold no secret state of their own.
    /// </summary>
    void IDisposable.Dispose()
    {
    }

    /// <summary>
    /// Attempts to unwrap a file key from a single stanza. Required override.
    /// </summary>
    /// <param name="stanza">One recipient stanza from the age header.</param>
    /// <returns>
    /// The 16-byte file key if this identity can unwrap the stanza;
    /// <c>null</c> if the stanza is addressed to a different identity.
    /// </returns>
    /// <exception cref="AgeFormatException">The stanza is malformed.</exception>
    byte[]? Unwrap(Stanza stanza);

    /// <summary>
    /// Attempts to unwrap a file key from any of the provided stanzas.
    /// The default implementation iterates stanzas one at a time, returning
    /// the first successful unwrap. Override for batch-based identity protocols
    /// (e.g. plugin identities) that need to see the full stanza list at once.
    /// </summary>
    byte[]? Unwrap(IReadOnlyList<Stanza> stanzas) =>
        stanzas.Select(Unwrap).OfType<byte[]>().FirstOrDefault();
}