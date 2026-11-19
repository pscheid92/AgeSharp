using System.Security.Cryptography;

namespace Age;

/// <summary>
/// The 16-byte symmetric key that protects one age file's payload, owning its own lifetime:
/// <see cref="Dispose"/> zeroes it, so <c>using</c> makes the guarantee syntactic.
/// </summary>
/// <remarks>
/// A bare <c>byte[]</c> cannot carry that guarantee — every site had to remember a
/// <c>try/finally</c>, and the ones that forgot were the S9 defects. Recipients and identities
/// see the key only as a span: <see cref="Recipients.IRecipient.Wrap"/> reads it, and
/// <see cref="Recipients.IIdentity.TryUnwrap(Format.Stanza, Span{byte})"/> writes it into the
/// buffer this owns.
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
    /// Asks each identity, in order, for the file key the stanzas wrap, and returns it from the
    /// first that has it, or null if none does.
    /// </summary>
    public static FileKey? UnwrapFrom(IReadOnlyList<Format.Stanza> stanzas, IEnumerable<Recipients.IIdentity> identities)
    {
        var key = new FileKey(new byte[Size]);

        try
        {
            foreach (var identity in identities)
            {
                if (identity.TryUnwrap(stanzas, key._bytes))
                    return key;
            }
        }
        catch
        {
            key.Dispose();
            throw;
        }

        key.Dispose();
        return null;
    }

    /// <summary>
    /// Hands a key an identity recovered into its own array over to the caller's buffer, and
    /// zeroes the array. Returns false, writing nothing, when there is no key.
    /// </summary>
    /// <exception cref="ArgumentException">The buffer is not <see cref="Size"/> bytes.</exception>
    /// <exception cref="AgeHeaderException">The recovered key is not <see cref="Size"/> bytes.</exception>
    public static bool Deliver(byte[]? recovered, Span<byte> into)
    {
        try
        {
            if (into.Length != Size)
                throw new ArgumentException($"the file key buffer must be {Size} bytes, got {into.Length}", nameof(into));

            if (recovered is null)
                return false;

            if (recovered.Length != Size)
                throw new AgeHeaderException($"file key must be {Size} bytes, got {recovered.Length}");

            recovered.CopyTo(into);
            return true;
        }
        finally
        {
            if (recovered is not null)
                CryptographicOperations.ZeroMemory(recovered);
        }
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
