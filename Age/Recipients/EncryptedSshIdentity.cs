using System.Security.Cryptography;
using AgeSharp.Crypto;
using AgeSharp;

namespace AgeSharp;

/// <summary>
/// An identity backed by a passphrase-protected SSH private key: ssh-ed25519 or ssh-rsa in
/// OpenSSH format, or ssh-rsa in the legacy PEM format. The public key is known without the
/// passphrase (stored unprotected in an OpenSSH key, given as the <c>.pub</c> file for a legacy
/// one), so the identity knows its recipient and which stanzas are addressed to it; it asks for
/// the passphrase only when a file is actually for this key, and then only until it has been
/// given the right one.
/// </summary>
public sealed class EncryptedSshIdentity : IIdentityWithRecipient, IDisposable
{
    private readonly Lock _lock = new();
    private readonly IProtectedSshKey _protectedKey;
    private readonly Func<string> _passphrase;
    private readonly string _keyType;
    private readonly string _tag;
    private IIdentity? _unlocked;
    private bool _unlocking;
    private bool _disposed;

    internal EncryptedSshIdentity(IProtectedSshKey protectedKey, Func<string> passphrase)
    {
        _protectedKey = protectedKey;
        _passphrase = passphrase;
        _keyType = SshKeyParser.KeyTypeOfWireBytes(protectedKey.PublicKey);
        _tag = SshKeyParser.ComputeTag(protectedKey.PublicKey);

        var authorizedKeysLine = $"{_keyType} {Convert.ToBase64String(protectedKey.PublicKey)}";
        Recipient = Recipients.ParseSsh(authorizedKeysLine);
    }

    /// <summary>The matching recipient, from the key's public key. Needs no passphrase.</summary>
    public IRecipient Recipient { get; }

    /// <summary>
    /// Parses a passphrase-protected SSH private key from PEM text (OpenSSH format).
    /// <paramref name="passphrase"/> is not called here, but later, by <see cref="TryUnwrap"/>.
    /// </summary>
    /// <exception cref="FormatException">
    /// The text is not a passphrase-protected ssh-ed25519 or ssh-rsa key in OpenSSH format. A
    /// key protected with a cipher or KDF this library does not read is accepted here, and
    /// refused by <see cref="TryUnwrap"/> once a file is addressed to it, before the passphrase
    /// is asked for.
    /// </exception>
    internal static EncryptedSshIdentity Parse(string pemText, Func<string> passphrase)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        ArgumentNullException.ThrowIfNull(passphrase);

        if (SshKeyParser.ParseProtectedKey(pemText) is { } protectedKey)
            return new EncryptedSshIdentity(protectedKey, passphrase);

        // Anything else is refused: for its own reason if it is malformed or protected in the
        // legacy PEM way, and otherwise for being a key that has no passphrase.
        SshKeyParser.ParsePrivateKey(pemText);
        throw new FormatException("the SSH private key is not passphrase-protected");
    }

    /// <summary>
    /// Tries to unwrap the file key from an SSH stanza. Returns false, without asking for the
    /// passphrase, for stanzas of other types or addressed to a different SSH key.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza is addressed to this key but is malformed.</exception>
    /// <exception cref="AgeException">
    /// The key cannot be decrypted here (its cipher, KDF or round count, or a browser
    /// limitation; said before the passphrase is asked for), the passphrase is wrong or could
    /// not be obtained, or the key file's public and private keys do not belong together.
    /// </exception>
    /// <exception cref="OperationCanceledException">The passphrase source was cancelled.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    /// <remarks>
    /// The identity stays locked while the passphrase source runs: other threads using it wait,
    /// and the source must not itself decrypt with this identity.
    /// </remarks>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        ArgumentNullException.ThrowIfNull(stanza);

        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (stanza.Type != _keyType || stanza.Args.Count < 1 || stanza.Args[0] != _tag)
                return false;

            if (_unlocked is null)
            {
                // The lock is reentrant: a passphrase source that decrypts with this identity
                // would get here again, ask itself again, and so on.
                if (_unlocking)
                    throw new AgeException("the passphrase source must not decrypt with the SSH key it is answering for");

                IIdentity unlocked;
                _unlocking = true;

                try
                {
                    unlocked = Unlock();
                }
                finally
                {
                    _unlocking = false;
                }

                // The passphrase source ran in between, and nothing stops it from disposing the
                // identity it is answering for.
                if (_disposed)
                {
                    (unlocked as IDisposable)?.Dispose();
                    ObjectDisposedException.ThrowIf(_disposed, this);
                }

                _unlocked = unlocked;
            }

            return _unlocked.TryUnwrap(stanza, fileKey);
        }
    }

    /// <summary>Disposes the decrypted key, if the passphrase was ever given.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
                return;

            _disposed = true;
            (_unlocked as IDisposable)?.Dispose();
        }
    }

    private IIdentity Unlock()
    {
        if (_protectedKey.WhyItCannotBeDecryptedHere() is { } reason)
            throw new AgeException($"failed to decrypt the SSH key: {reason}");

        string passphrase;

        try
        {
            passphrase = _passphrase();
        }
        catch (Exception ex) when (ex is not AgeException and not OperationCanceledException)
        {
            throw new AgeException($"failed to obtain the passphrase for the SSH key: {ex.Message}", ex);
        }

        (string keyType, byte[] publicWireBytes, Org.BouncyCastle.Crypto.AsymmetricKeyParameter privateKey) key;

        try
        {
            key = _protectedKey.Unprotect(passphrase ?? "");
        }
        catch (CryptographicException ex)
        {
            throw new AgeException("failed to decrypt the SSH key: incorrect passphrase", ex);
        }
        catch (FormatException ex)
        {
            throw new AgeException($"failed to decrypt the SSH key: {ex.Message}", ex);
        }

        // The recipient and the stanza match came from the public key read without the
        // passphrase; a file whose private key is another's would otherwise answer for a key
        // it does not hold.
        if (!key.publicWireBytes.AsSpan().SequenceEqual(_protectedKey.PublicKey))
            throw new AgeException("mismatched private and public SSH key");

        return key.keyType == "ssh-ed25519"
            ? SshEd25519Identity.FromParsedKey(key.keyType, key.publicWireBytes, key.privateKey)
            : SshRsaIdentity.FromParsedKey(key.keyType, key.publicWireBytes, key.privateKey);
    }
}
