using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;

namespace Age.Recipients;

/// <summary>
/// An identity backed by a passphrase-protected SSH private key (OpenSSH format, ssh-ed25519
/// or ssh-rsa). The public key is stored unprotected, so the identity knows its recipient and
/// which stanzas are addressed to it without the passphrase; it asks for the passphrase only
/// when a file is actually for this key, and then only until it has been given the right one.
/// </summary>
public sealed class EncryptedSshIdentity : IIdentity, IDisposable
{
    private readonly Lock _lock = new();
    private readonly ProtectedOpenSshKey _protectedKey;
    private readonly Func<string> _passphrase;
    private readonly string _keyType;
    private readonly string _tag;
    private IIdentity? _unlocked;
    private bool _disposed;

    internal EncryptedSshIdentity(ProtectedOpenSshKey protectedKey, Func<string> passphrase)
    {
        _protectedKey = protectedKey;
        _passphrase = passphrase;
        _keyType = SshKeyParser.KeyTypeOfWireBytes(protectedKey.PublicKey);
        _tag = SshKeyParser.ComputeTag(protectedKey.PublicKey);

        var authorizedKeysLine = $"{_keyType} {Convert.ToBase64String(protectedKey.PublicKey)}";
        Recipient = AgeKeygen.ParseSshRecipient(authorizedKeysLine);
    }

    /// <summary>The matching recipient, from the key file's public key. Needs no passphrase.</summary>
    public IRecipient Recipient { get; }

    /// <summary>
    /// Parses a passphrase-protected SSH private key from PEM text (OpenSSH format).
    /// <paramref name="passphrase"/> is not called here, but later, by <see cref="Unwrap"/>.
    /// </summary>
    /// <exception cref="FormatException">
    /// The text is not a passphrase-protected ssh-ed25519 or ssh-rsa key in OpenSSH format, or
    /// it uses a cipher or KDF this library does not read.
    /// </exception>
    public static EncryptedSshIdentity Parse(string pemText, Func<string> passphrase)
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
    /// Attempts to unwrap the file key from an SSH stanza. Returns null, without asking for the
    /// passphrase, for stanzas of other types or addressed to a different SSH key.
    /// </summary>
    /// <exception cref="AgeHeaderException">The stanza is addressed to this key but is malformed.</exception>
    /// <exception cref="AgeException">
    /// The passphrase is wrong, could not be obtained, or the key file's public and private
    /// keys do not belong together.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        ArgumentNullException.ThrowIfNull(stanza);

        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (stanza.Type != _keyType || stanza.Args.Count < 1 || stanza.Args[0] != _tag)
                return null;

            if (_unlocked is null)
            {
                var unlocked = Unlock();

                // The passphrase source ran in between, and nothing stops it from disposing the
                // identity it is answering for.
                if (_disposed)
                {
                    (unlocked as IDisposable)?.Dispose();
                    ObjectDisposedException.ThrowIf(_disposed, this);
                }

                _unlocked = unlocked;
            }

            return _unlocked.Unwrap(stanza);
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
        catch (Exception ex) when (ex is not AgeException)
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

        // The recipient and the stanza match came from the unprotected public key; a file
        // whose private key is another's would otherwise answer for a key it does not hold.
        if (!key.publicWireBytes.AsSpan().SequenceEqual(_protectedKey.PublicKey))
            throw new AgeException("mismatched private and public SSH key");

        return key.keyType == "ssh-ed25519"
            ? SshEd25519Identity.FromParsedKey(key.keyType, key.publicWireBytes, key.privateKey)
            : SshRsaIdentity.FromParsedKey(key.keyType, key.publicWireBytes, key.privateKey);
    }
}
