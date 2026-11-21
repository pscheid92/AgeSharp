namespace AgeSharp;

/// <summary>
/// An identity that already knows the file key: it offers that key for any stanza, so a file can
/// be decrypted with a key obtained elsewhere, from <see cref="Identities.UnwrapFileKey"/> for
/// instance. go-age calls this <c>NewInjectedFileKeyIdentity</c>.
/// </summary>
/// <remarks>
/// The header's MAC is still verified, so a key that is not the file's fails as an
/// <see cref="AgeAuthenticationException"/>. A low-level identity most users do not need: see the
/// remarks on <see cref="FileKey"/>. Disposing clears its copy of the key.
/// </remarks>
public sealed class FileKeyIdentity : IIdentity
{
    private readonly FileKey _fileKey;

    /// <summary>An identity offering <paramref name="fileKey"/>, which is copied: dispose yours as you would.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="fileKey"/> is null.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="fileKey"/> has been disposed.</exception>
    public FileKeyIdentity(FileKey fileKey)
    {
        ArgumentNullException.ThrowIfNull(fileKey);
        _fileKey = FileKey.From(fileKey.Bytes);
    }

    /// <summary>Writes the key, for any stanza: whether it is the file's, the header's MAC decides.</summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        var key = _fileKey.Bytes;

        if (fileKey.Length != FileKey.Size)
            throw new ArgumentException($"the file key buffer must be {FileKey.Size} bytes, got {fileKey.Length}", nameof(fileKey));

        key.CopyTo(fileKey);
        return true;
    }

    /// <summary>Clears the key.</summary>
    public void Dispose() => _fileKey.Dispose();
}
