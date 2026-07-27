using System.Security.Cryptography;

namespace Age;

/// <summary>
/// The 16-byte symmetric key that protects one age file's payload, owning its own lifetime:
/// <see cref="Dispose"/> zeroes it, so <c>using</c> makes the guarantee syntactic.
/// </summary>
/// <remarks>
/// A bare <c>byte[]</c> cannot carry that guarantee — every site had to remember a
/// <c>try/finally</c>, and the ones that forgot were the S9 defects. Internal on purpose:
/// <see cref="Recipients.IRecipient.Wrap"/> and <c>IIdentity.Unwrap</c> are
/// shipped public API taking and returning spans and arrays, so this wraps the key inside the
/// library without changing what a consumer sees.
/// </remarks>
internal sealed class FileKey : IDisposable
{
    internal const int Size = 16;

    private readonly byte[] _bytes;
    private bool _disposed;

    private FileKey(byte[] bytes) => _bytes = bytes;

    /// <summary>The key material. Valid until <see cref="Dispose"/>.</summary>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public ReadOnlySpan<byte> Bytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _bytes;
        }
    }

    /// <summary>Generates a new file key from CSPRNG output.</summary>
    public static FileKey Fresh()
    {
        var bytes = new byte[Size];
        RandomNumberGenerator.Fill(bytes);
        return new FileKey(bytes);
    }

    /// <summary>
    /// Takes ownership of a key recovered by an identity, which hands back a <c>byte[]</c>
    /// because <c>IIdentity.Unwrap</c> is shipped public API. The array is
    /// zeroed on <see cref="Dispose"/>; the caller must not keep a reference to it.
    /// </summary>
    /// <exception cref="AgeHeaderException">
    /// The identity returned something other than <see cref="Size"/> bytes. Custom and plugin
    /// identities are caller-supplied code and can return anything; a wrong-sized key would
    /// derive garbage rather than fail.
    /// </exception>
    public static FileKey Adopt(byte[] bytes)
    {
        if (bytes.Length == Size)
            return new FileKey(bytes);

        CryptographicOperations.ZeroMemory(bytes);
        throw new AgeHeaderException($"file key must be {Size} bytes, got {bytes.Length}");
    }

    /// <summary>Zeroes the key material. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_bytes);
    }
}
