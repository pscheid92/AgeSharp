
namespace AgeSharp;

/// <summary>
/// An <see cref="IIdentity"/> that can derive its own public half. Implement this
/// when the recipient is recoverable from the identity's key material, so callers
/// can go from a secret key to the matching recipient without knowing the concrete
/// type — for example to encrypt to the identities in a key file (<c>age -e -i</c>).
/// </summary>
/// <remarks>
/// Optional second interface, mirroring <see cref="IRecipientWithLabels"/>: the base
/// <see cref="IIdentity"/> stays a one-method seam, and identities that cannot derive
/// a recipient — plugin identities, or any identity whose secret lives behind a remote
/// service — simply do not implement this. Test with <c>is IIdentityWithRecipient</c>
/// rather than switching over concrete types.
/// </remarks>
public interface IIdentityWithRecipient : IIdentity
{
    /// <summary>
    /// The public recipient matching this identity.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    IRecipient Recipient { get; }
}
