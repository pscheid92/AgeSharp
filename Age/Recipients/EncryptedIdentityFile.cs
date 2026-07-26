using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AgeSharp;

/// <summary>
///     A passphrase-protected identity file, usable directly as an <see cref="IIdentity" />.
///     Decryption is deferred until a stanza is actually tried against it, so the passphrase
///     is requested only when this file is needed — pass several and you are prompted for
///     the one that matters, not all of them.
/// </summary>
/// <remarks>
///     Deliberately not an <see cref="IIdentityWithRecipient" />: one file can hold several
///     identities, and that interface's single <c>Recipient</c> could only report the first.
///     Use <see cref="Recipients" /> instead.
/// </remarks>
public sealed class EncryptedIdentityFile : IIdentity
{
    private readonly byte[] _contents;
    private readonly Func<char[]> _passphrase;
    private readonly IPluginCallbacks? _plugins;

    private bool _disposed;
    private IReadOnlyList<IIdentity>? _identities;

    /// <summary>Wraps the contents of a passphrase-encrypted identity file.</summary>
    /// <param name="contents">The encrypted file, binary or ASCII-armored. Ciphertext, so it is copied but not treated as secret.</param>
    /// <param name="passphrase">
    ///     Called at most once, when the file is first needed. The array it returns is zeroed
    ///     as soon as the passphrase has been used, so return a fresh one.
    /// </param>
    /// <param name="plugins">Callbacks for any plugin identities the file contains.</param>
    /// <exception cref="ArgumentNullException"><paramref name="passphrase" /> is null.</exception>
    public EncryptedIdentityFile(ReadOnlySpan<byte> contents, Func<char[]> passphrase,
                                 IPluginCallbacks? plugins = null)
    {
        ArgumentNullException.ThrowIfNull(passphrase);

        _contents = contents.ToArray();
        _passphrase = passphrase;
        _plugins = plugins;
    }

    /// <summary>
    ///     The recipients matching the identities in this file, for encrypting to a key you
    ///     hold. Decrypts the file on first access, prompting for the passphrase.
    /// </summary>
    /// <exception cref="AgeException">The passphrase was wrong, or the file is not passphrase-encrypted.</exception>
    public IReadOnlyList<IRecipient> Recipients =>
        [.. Decrypted().OfType<IIdentityWithRecipient>().Select(i => i.Recipient)];

    /// <inheritdoc />
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) =>
        TryUnwrap([stanza], fileKey);

    /// <inheritdoc />
    public bool TryUnwrap(IReadOnlyList<Stanza> stanzas, Span<byte> fileKey)
    {
        foreach (var identity in Decrypted())
            if (identity.TryUnwrap(stanzas, fileKey))
                return true;

        return false;
    }

    /// <summary>Disposes the identities this file decrypted to, if any.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        foreach (var identity in _identities ?? [])
            identity.Dispose();

        _identities = null;
    }

    private IReadOnlyList<IIdentity> Decrypted()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_identities is not null)
            return _identities;

        var chars = _passphrase() ?? throw new AgeException("no passphrase was supplied for the identity file");

        using var plaintext = new MemoryStream();

        try
        {
            using var passphrase = new Passphrase(chars);
            Age.Decrypt(new MemoryStream(_contents, false), plaintext, [passphrase]);
        }
        catch (NoIdentityMatchException)
        {
            throw new AgeException("identity file is age-encrypted, but not with a passphrase");
        }
        finally
        {
            // ZeroMemory has no char overload; reinterpret rather than Array.Clear, which
            // the JIT may elide.
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
        }

        try
        {
            // The decrypted file holds AGE-SECRET-KEY lines. ParseIdentities takes a string,
            // which cannot be zeroed — the buffers on either side of it can be, and are.
            _identities = Age.ParseIdentities(Encoding.UTF8.GetString(plaintext.GetBuffer(), 0, (int)plaintext.Length),
                                          _plugins);
            return _identities;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext.GetBuffer());
        }
    }
}
