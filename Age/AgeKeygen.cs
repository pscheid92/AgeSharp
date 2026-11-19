using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Plugin;
using Age.Recipients;

namespace Age;

/// <summary>
/// Key generation and key/identity-file parsing: single keys, recipients files
/// (<c>-R</c> style), plaintext identity files (<c>-i</c> style), and
/// passphrase-protected identity files.
/// </summary>
public static class AgeKeygen
{
    /// <summary>Generates a new X25519 identity (the <c>age-keygen</c> default).</summary>
    public static X25519Identity Generate() =>
        X25519Identity.Generate();

    /// <summary>Parses an X25519 secret key (<c>AGE-SECRET-KEY-1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 secret key.</exception>
    public static X25519Identity ParseIdentity(string s) =>
        X25519Identity.Parse(s);

    /// <summary>Parses an X25519 recipient (<c>age1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid X25519 recipient.</exception>
    public static X25519Recipient ParseRecipient(string s) =>
        X25519Recipient.Parse(s);

    /// <summary>Generates a new post-quantum ML-KEM-768-X25519 identity.</summary>
    public static MlKem768X25519Identity GeneratePq() =>
        MlKem768X25519Identity.Generate();

    /// <summary>Parses an ML-KEM-768-X25519 secret key (<c>AGE-SECRET-KEY-PQ-1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid ML-KEM-768-X25519 secret key.</exception>
    public static MlKem768X25519Identity ParsePqIdentity(string s) =>
        MlKem768X25519Identity.Parse(s);

    /// <summary>Parses an ML-KEM-768-X25519 recipient (<c>age1pq1…</c>).</summary>
    /// <exception cref="FormatException">The string is not a valid ML-KEM-768-X25519 recipient.</exception>
    public static MlKem768X25519Recipient ParsePqRecipient(string s) =>
        MlKem768X25519Recipient.Parse(s);

    /// <summary>
    /// Parses an SSH public key from an authorized_keys line and returns the appropriate recipient.
    /// Supports ssh-ed25519 and ssh-rsa key types.
    /// </summary>
    public static IRecipient ParseSshRecipient(string authorizedKeysLine)
    {
        var (keyType, _, _) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Recipient.Parse(authorizedKeysLine),
            "ssh-rsa" => SshRsaRecipient.Parse(authorizedKeysLine),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    /// <summary>
    /// Parses an SSH private key from PEM text and returns the appropriate identity.
    /// Supports ssh-ed25519 and ssh-rsa key types in OpenSSH, PKCS#1, or PKCS#8 format.
    /// </summary>
    /// <exception cref="FormatException">
    /// The key is malformed or of another type, or it is passphrase-protected: use
    /// <see cref="ParseSshIdentity(string, Func{string})"/> for a key that may be.
    /// </exception>
    public static IIdentity ParseSshIdentity(string pemText)
    {
        var (keyType, publicWireBytes, privateKey) = SshKeyParser.ParsePrivateKey(pemText);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Identity.FromParsedKey(keyType, publicWireBytes, privateKey),
            "ssh-rsa" => SshRsaIdentity.FromParsedKey(keyType, publicWireBytes, privateKey),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    /// <summary>
    /// Parses an SSH private key that may be passphrase-protected. A protected key (OpenSSH
    /// format) becomes an <see cref="EncryptedSshIdentity"/>, which asks
    /// <paramref name="passphrase"/> only once a file addressed to the key is decrypted; an
    /// unprotected key is parsed as by <see cref="ParseSshIdentity(string)"/> and never asks.
    /// </summary>
    /// <exception cref="FormatException">
    /// The key is malformed, of another type, or protected in the legacy PEM way, which does
    /// not store its public key: use <see cref="ParseSshIdentity(string, string, Func{string})"/>
    /// with its <c>.pub</c> file for that. A key protected with a cipher or KDF this library
    /// does not read is accepted, and refused once a file is addressed to it, before the
    /// passphrase is asked for.
    /// </exception>
    public static IIdentity ParseSshIdentity(string pemText, Func<string> passphrase)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        ArgumentNullException.ThrowIfNull(passphrase);

        return SshKeyParser.ParseProtectedKey(pemText) is { } protectedKey
            ? new EncryptedSshIdentity(protectedKey, passphrase)
            : ParseSshIdentity(pemText);
    }

    /// <summary>
    /// Parses an SSH private key that may be passphrase-protected, together with its public
    /// key (the <c>.pub</c> file). This also reads ssh-rsa keys protected in the legacy PEM
    /// format (<c>BEGIN RSA PRIVATE KEY</c> with <c>Proc-Type: 4,ENCRYPTED</c>), which do not
    /// store their public key, as go-age does: the public key decides which files are for
    /// the key, <paramref name="passphrase"/> is asked only once one is decrypted, and the
    /// decrypted key must then match the public key. Other keys are read as by
    /// <see cref="ParseSshIdentity(string, Func{string})"/>, and must match the public key.
    /// </summary>
    /// <param name="pemText">The private key file.</param>
    /// <param name="publicKey">The public key file's text: an authorized_keys line.</param>
    /// <param name="passphrase">Asked for the passphrase when a file is for a protected key.</param>
    /// <exception cref="FormatException">
    /// The private or public key is malformed or of another type, the public key does not
    /// belong to a key file that names its own, or the key is encrypted PKCS#8 (not read, as
    /// in go-age). A key protected with a cipher this library does not decrypt is accepted,
    /// and refused once a file is addressed to it, before the passphrase is asked for.
    /// </exception>
    public static IIdentity ParseSshIdentity(string pemText, string publicKey, Func<string> passphrase)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(passphrase);

        var (publicKeyType, publicWireBytes, _) = SshKeyParser.ParsePublicKey(publicKey);

        if (LegacyPemSshKey.IsLegacyProtected(pemText))
        {
            if (publicKeyType != "ssh-rsa")
                throw new FormatException($"a legacy PEM SSH key is an ssh-rsa key, but the public key is {publicKeyType}");

            return new EncryptedSshIdentity(LegacyPemSshKey.Parse(pemText, publicWireBytes), passphrase);
        }

        if (SshKeyParser.ParseProtectedKey(pemText) is { } protectedKey)
        {
            RequireSamePublicKey(protectedKey.PublicKey, publicWireBytes);
            return new EncryptedSshIdentity(protectedKey, passphrase);
        }

        var (keyType, ownPublicKey, privateKey) = SshKeyParser.ParsePrivateKey(pemText);
        RequireSamePublicKey(ownPublicKey, publicWireBytes);

        return keyType switch
        {
            "ssh-ed25519" => SshEd25519Identity.FromParsedKey(keyType, ownPublicKey, privateKey),
            "ssh-rsa" => SshRsaIdentity.FromParsedKey(keyType, ownPublicKey, privateKey),
            _ => throw new FormatException($"unsupported SSH key type: {keyType}")
        };
    }

    private static void RequireSamePublicKey(byte[] ownPublicKey, byte[] given)
    {
        if (!ownPublicKey.AsSpan().SequenceEqual(given))
            throw new FormatException("the public key does not belong to the SSH private key");
    }

    /// <summary>
    /// Parses a recipients file containing public keys, comments, and blank lines.
    /// Supports age X25519 (age1...), ML-KEM-768 (age1pq...), tagged (age1tag1..., age1tagpq1...), plugin (age1name1...), and SSH public keys.
    /// The returned array converts implicitly to the <c>ReadOnlySpan&lt;IRecipient&gt;</c>
    /// that <see cref="AgeEncrypt.Encrypt(Stream, Stream, ReadOnlySpan{IRecipient})"/> accepts.
    /// </summary>
    public static IRecipient[] ParseRecipientsFile(string text, IPluginCallbacks? callbacks = null) =>
        text.Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(line => ParseRecipientLine(line, callbacks))
            .ToArray();

    /// <summary>
    /// Parses a single recipient string: age X25519, ML-KEM-768, plugin, or SSH public key.
    /// </summary>
    internal static IRecipient ParseRecipientLine(string line, IPluginCallbacks? callbacks)
    {
        // Dispatch on the true bech32 HRP — everything before the LAST '1' (BIP-173), since
        // data never contains '1'. String prefixes are ambiguous here: 'p' and 'q' are data
        // characters, so an X25519 recipient's data can itself start with "pq" ("age1pq...").
        var sep = line.LastIndexOf('1');
        var hrp = sep > 0 ? line[..sep] : "";

        return hrp switch
        {
            "age" => X25519Recipient.Parse(line),
            "age1pq" => MlKem768X25519Recipient.Parse(line),
            "age1tag" => P256TagRecipient.Parse(line),
            "age1tagpq" => MlKem768P256TagRecipient.Parse(line),
            _ when hrp.StartsWith("age1", StringComparison.Ordinal) => new PluginRecipient(line, callbacks),
            _ when line.StartsWith("ssh-", StringComparison.Ordinal) => ParseSshRecipient(line),
            _ => throw new FormatException($"unrecognized recipient: {line}")
        };
    }

    /// <summary>
    /// Parses a plaintext identity file containing AGE-SECRET-KEY lines, plugin identities, comments, and blank lines.
    /// The returned array converts implicitly to the <c>ReadOnlySpan&lt;IIdentity&gt;</c>
    /// that <see cref="AgeEncrypt.Decrypt(Stream, Stream, ReadOnlySpan{IIdentity})"/> accepts.
    /// </summary>
    /// <exception cref="FormatException">
    /// A line is not a valid identity. The message names the line by number and never quotes it.
    /// </exception>
    public static IIdentity[] ParseIdentityFile(string text, IPluginCallbacks? callbacks = null)
    {
        var identities = new List<IIdentity>();
        var lines = text.Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            identities.Add(ParseIdentityLine(line, lineNumber: i + 1, callbacks));
        }

        return [.. identities];
    }

    /// <remarks>
    /// Errors cite <paramref name="lineNumber"/> instead of the line, as go-age does: a line that
    /// fails to parse is often a secret key with a stray space or the wrong case, and exception
    /// messages end up in logs and terminals. The parsers' own messages are safe to pass on —
    /// at most they name a single offending character.
    /// </remarks>
    private static IIdentity ParseIdentityLine(string line, int lineNumber, IPluginCallbacks? callbacks)
    {
        try
        {
            if (line.StartsWith("AGE-SECRET-KEY-PQ-", StringComparison.Ordinal))
                return MlKem768X25519Identity.Parse(line);

            if (line.StartsWith("AGE-SECRET-KEY-", StringComparison.Ordinal))
                return X25519Identity.Parse(line);

            if (line.StartsWith("AGE-PLUGIN-", StringComparison.Ordinal))
                return new PluginIdentity(line, callbacks);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"invalid identity on line {lineNumber}: {ex.Message}", ex);
        }

        throw new FormatException(
            $"unrecognized line {lineNumber} in identity file: expected AGE-SECRET-KEY-1..., " +
            "AGE-SECRET-KEY-PQ-1... or AGE-PLUGIN-... with no surrounding whitespace");
    }

    /// <summary>
    /// Decrypts an encrypted (passphrase-protected) identity file and parses the contained identities.
    /// </summary>
    /// <remarks>
    ///     The decrypted file contains <c>AGE-SECRET-KEY-1…</c> lines in the clear. The byte
    ///     copies are cleared here; the <see cref="string" /> they are decoded into cannot be,
    ///     because <see cref="ParseIdentityFile" /> takes a string and is shipped public API.
    ///     Treat this as reducing the exposure rather than eliminating it.
    /// </remarks>
    public static IIdentity[] DecryptIdentityFile(byte[] data, string passphrase)
    {
        using var input = new MemoryStream(data);

        // Sized up front: the plaintext is always shorter than the file, so the buffer never
        // grows. A growing MemoryStream abandons each outgrown buffer with a copy of the private
        // keys in it, where the clearing below cannot reach.
        using var output = new MemoryStream(data.Length);

        AgeEncrypt.Decrypt(input, output, new ScryptRecipient(passphrase));

        // ToArray copies out, and the MemoryStream's own buffer keeps the plaintext too —
        // Dispose does not clear it. Both are private keys in the clear.
        var plaintextBytes = output.ToArray();

        try
        {
            return ParseIdentityFile(Encoding.UTF8.GetString(plaintextBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(output.GetBuffer());
        }
    }

    /// <summary>
    /// Encrypts an identity file with a passphrase using scrypt.
    /// </summary>
    /// <remarks>
    ///     <paramref name="identityFileText" /> holds private keys in the clear. The UTF-8 copy
    ///     made here is cleared; the caller's string cannot be.
    /// </remarks>
    public static byte[] EncryptIdentityFile(string identityFileText, string passphrase, bool armor = false, int workFactor = 18)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(identityFileText);

        try
        {
            using var input = new MemoryStream(plaintextBytes);
            using var output = new MemoryStream();

            AgeEncrypt.Encrypt(input, output, armor, new ScryptRecipient(passphrase, workFactor));
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }
}