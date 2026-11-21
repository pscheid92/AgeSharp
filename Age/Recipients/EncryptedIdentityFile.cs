using System.Security.Cryptography;
using System.Text;

namespace AgeSharp;

/// <summary>
/// A passphrase-protected identity file, as an identity in its own right: an identity file
/// encrypted to a <see cref="Passphrase"/>, as <c>age -p</c> writes one. It is decrypted only when
/// a file is first tried against it, so the passphrase is asked for only when needed: given
/// several, only the one that opens the file asks.
/// </summary>
/// <remarks>
/// <para>
/// Not an <see cref="IIdentityWithRecipient"/>: one file can hold several identities, and that
/// interface's single recipient could name only one. <see cref="GetRecipients"/> names them all.
/// </para>
/// <para>
/// AgeSharp's own identities are tried before this one (see <see cref="Identities"/>), so a file
/// one of them opens never asks for this passphrase. Disposing clears the identities decrypted
/// from the file.
/// </para>
/// </remarks>
public sealed class EncryptedIdentityFile : IIdentity
{
    private readonly byte[] _contents;
    private readonly Func<char[]> _passphrase;
    private readonly IPluginCallbacks? _plugins;
    private Identities? _identities;
    private bool _disposed;

    /// <summary>An encrypted identity file, read no further than copying it until it is needed.</summary>
    /// <param name="contents">The encrypted file, binary or armored. Ciphertext, so copied but not treated as secret.</param>
    /// <param name="passphrase">
    /// Asked once, when the file is first needed, and again only if that attempt failed. The
    /// characters it returns are cleared once used, so return a fresh array.
    /// </param>
    /// <param name="plugins">Lets plugin identities in the file talk to the user.</param>
    /// <exception cref="ArgumentNullException"><paramref name="passphrase"/> is null.</exception>
    public EncryptedIdentityFile(ReadOnlySpan<byte> contents, Func<char[]> passphrase, IPluginCallbacks? plugins = null)
    {
        _contents = contents.ToArray();
        _passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));
        _plugins = plugins;
    }

    /// <summary>
    /// The recipients of the identities in the file, for encrypting to keys you hold. Decrypts
    /// the file if it has not been, asking for the passphrase.
    /// </summary>
    /// <exception cref="AgeException">The passphrase is wrong, or the file is not an identity file encrypted to one.</exception>
    public IReadOnlyList<IRecipient> GetRecipients() =>
        [.. Unlocked().OfType<IIdentityWithRecipient>().Select(i => i.Recipient)];

    /// <summary>
    /// Unwraps the file key with the identities in the file, decrypting it first if it has not
    /// been: false if none of them opens the stanza.
    /// </summary>
    /// <exception cref="AgeException">The passphrase is wrong, or the file is not an identity file encrypted to one.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        foreach (var identity in Unlocked())
        {
            if (identity.TryUnwrap(stanza, fileKey))
                return true;
        }

        return false;
    }

    private Identities Unlocked()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _identities ??= Decrypt();
    }

    private Identities Decrypt()
    {
        var characters = _passphrase() ?? throw new InvalidOperationException("the passphrase callback returned null");
        byte[] plaintext;

        try
        {
            using var passphrase = new Passphrase(characters.AsSpan());
            plaintext = new Identities(passphrase).Decrypt(_contents);
        }
        catch (NoIdentityMatchException ex)
        {
            // Not a match for the file being decrypted, which would be the reader's conclusion
            // if this went through: this file could not be opened at all.
            throw new AgeException("the identity file's passphrase is wrong, or it is not encrypted to a passphrase", ex);
        }
        finally
        {
            Array.Clear(characters);
        }

        try
        {
            // The decoded string holds the keys too, and cannot be cleared; the bytes can.
            return Identities.Parse(Encoding.UTF8.GetString(plaintext), _plugins);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Disposes the identities decrypted from the file, if it was.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _identities?.Dispose();
    }
}
