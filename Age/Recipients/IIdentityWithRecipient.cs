namespace Age.Recipients;

/// <summary>
/// An <see cref="IIdentity"/> that knows its own public half, so a caller can go from a secret
/// key to the recipient that encrypts to it without knowing the concrete type: for example, to
/// encrypt to the identities in a key file.
/// </summary>
/// <remarks>
/// A second, optional interface, so <see cref="IIdentity"/> stays a one-method seam. An identity
/// that cannot derive its recipient (one whose secret lives behind a remote service, say) does
/// not implement it. Test with <c>is IIdentityWithRecipient</c>.
/// </remarks>
public interface IIdentityWithRecipient : IIdentity
{
    /// <summary>The recipient that encrypts to this identity.</summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    IRecipient Recipient { get; }
}
