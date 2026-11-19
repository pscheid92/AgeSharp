using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Age.Crypto;

/// <summary>
/// A passphrase-protected private key in OpenSSH's own format (<c>openssh-key-v1</c>): the
/// public key in the clear, and the private key encrypted under a key derived from the
/// passphrase with bcrypt_pbkdf.
/// </summary>
/// <remarks>
/// The container is read here, without the passphrase, for what age needs before it asks for
/// one: the public key. Decrypting is left to SSH.NET, which implements bcrypt_pbkdf and the
/// ciphers OpenSSH protects keys with; neither .NET nor BouncyCastle has bcrypt_pbkdf. What
/// SSH.NET returns is then held to the same standard as an unprotected key.
/// </remarks>
internal sealed class ProtectedOpenSshKey : IProtectedSshKey
{
    // bcrypt_pbkdf costs time linear in the round count, and the count comes from the file:
    // OpenSSH sets no upper bound, and neither does SSH.NET. 2048 is the bound Go's ssh
    // package, and so go-age, applies — some fifteen seconds of work on a current laptop, not
    // the months a hostile file could ask for.
    private const uint MaxRounds = 1 << 11;

    private static ReadOnlySpan<byte> Magic => "openssh-key-v1\0"u8;

    // The ciphers SSH.NET decrypts OpenSSH keys with.
    private static readonly HashSet<string> Ciphers =
    [
        "aes128-ctr", "aes192-ctr", "aes256-ctr",
        "aes128-cbc", "aes192-cbc", "aes256-cbc",
        "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com", "3des-cbc",
    ];

    private readonly byte[] _blob;
    private readonly string _cipher;
    private readonly string? _whyItCannotBeDecrypted;

    private ProtectedOpenSshKey(byte[] blob, string cipher, byte[] publicKey, string? whyItCannotBeDecrypted)
    {
        _blob = blob;
        _cipher = cipher;
        PublicKey = publicKey;
        _whyItCannotBeDecrypted = whyItCannotBeDecrypted;
    }

    /// <summary>The public key in SSH wire format, readable without the passphrase.</summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Whether a key blob names a cipher other than "none". The cipher is the first field after
    /// the magic, so this is decidable before anything encrypted is touched. A blob too short to
    /// say is left for the parser to reject as malformed.
    /// </summary>
    public static bool IsProtected(ReadOnlySpan<byte> blob)
    {
        if (!blob.StartsWith(Magic) || blob.Length < Magic.Length + 4)
            return false;

        var cipherLength = BinaryPrimitives.ReadUInt32BigEndian(blob[Magic.Length..]);
        var cipher = blob[(Magic.Length + 4)..];

        return cipherLength <= (uint)cipher.Length && !cipher[..(int)cipherLength].SequenceEqual("none"u8);
    }

    /// <summary>Reads the container, without decrypting anything.</summary>
    /// <exception cref="FormatException">The blob is malformed or not passphrase-protected.</exception>
    public static ProtectedOpenSshKey Parse(ReadOnlySpan<byte> blob)
    {
        if (!blob.StartsWith(Magic))
            throw new FormatException("invalid OpenSSH private key: missing openssh-key-v1 magic");

        var rest = blob[Magic.Length..];
        var cipherName = ReadString(ref rest);
        var kdfName = ReadString(ref rest);
        var kdfOptions = ReadString(ref rest);
        var keyCount = ReadUInt32(ref rest);
        var publicKey = ReadString(ref rest);
        ReadString(ref rest); // the encrypted section

        if (cipherName.SequenceEqual("none"u8))
            throw new FormatException("the SSH private key is not passphrase-protected");

        if (keyCount != 1)
            throw new FormatException($"an OpenSSH private key file must hold exactly one key, got {keyCount}");

        var cipher = Printable(cipherName);
        return new ProtectedOpenSshKey(blob.ToArray(), cipher, publicKey.ToArray(), WhyItCannotBeDecrypted(cipher, kdfName, kdfOptions));
    }

    /// <summary>
    /// Why this library cannot decrypt a key protected like this, or null if it can: the
    /// cipher, the KDF and its round count, all readable without the passphrase.
    /// </summary>
    /// <remarks>
    /// Kept for when a file is addressed to the key rather than thrown when the key file is
    /// read: as in go-age, a key that is never needed does not stop anything.
    /// </remarks>
    private static string? WhyItCannotBeDecrypted(string cipher, ReadOnlySpan<byte> kdfName, ReadOnlySpan<byte> kdfOptions)
    {
        if (!kdfName.SequenceEqual("bcrypt"u8))
            return $"unsupported SSH private key KDF: {Printable(kdfName)}";

        if (!Ciphers.Contains(cipher))
            return $"unsupported SSH private key cipher: {cipher}";

        try
        {
            var salt = ReadString(ref kdfOptions);
            var rounds = ReadUInt32(ref kdfOptions);

            if (salt.IsEmpty || rounds == 0 || !kdfOptions.IsEmpty)
                return "invalid OpenSSH private key: malformed bcrypt options";

            return rounds > MaxRounds
                ? $"SSH private key asks for {rounds} bcrypt rounds, more than the maximum of {MaxRounds}"
                : null;
        }
        catch (FormatException)
        {
            return "invalid OpenSSH private key: malformed bcrypt options";
        }
    }

    /// <summary>
    /// Why this key cannot be decrypted here, or null if it can. Asked before the passphrase is,
    /// so nobody types one that cannot be used.
    /// </summary>
    public string? WhyItCannotBeDecryptedHere() =>
        _whyItCannotBeDecrypted
        ?? (OperatingSystem.IsBrowser() ? WhyItCannotBeDecryptedInTheBrowser(SshKeyParser.KeyTypeOfWireBytes(PublicKey), _cipher) : null);

    /// <summary>
    /// Why a protected key of this type and cipher cannot be decrypted in the browser, or null
    /// if it can.
    /// </summary>
    /// <remarks>
    /// A browser has no platform AES, 3DES or RSA, and SSH.NET uses them: for AES-CTR and
    /// AES-CBC, for 3DES, and for every RSA key it decrypts. Its AES-GCM and ChaCha20-Poly1305
    /// are BouncyCastle's. Only what was checked in Blazor WebAssembly is let through.
    /// </remarks>
    internal static string? WhyItCannotBeDecryptedInTheBrowser(string keyType, string cipher)
    {
        if (keyType == "ssh-rsa")
            return "passphrase-protected ssh-rsa keys cannot be decrypted in the browser; " +
                   "use an ssh-ed25519 key protected with aes256-gcm@openssh.com";

        return cipher is "aes256-gcm@openssh.com" or "chacha20-poly1305@openssh.com"
            ? null
            : $"SSH keys protected with {cipher} cannot be decrypted in the browser; " +
              "re-protect a copy with ssh-keygen -p -Z aes256-gcm@openssh.com";
    }

    /// <summary>Decrypts the private key.</summary>
    /// <exception cref="CryptographicException">
    /// The passphrase is wrong (or the encrypted section is damaged; the two are indistinguishable).
    /// </exception>
    /// <exception cref="FormatException">
    /// What the passphrase decrypts is not a usable ssh-ed25519 or ssh-rsa key.
    /// </exception>
    public (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) Unprotect(string passphrase)
    {
        if (WhyItCannotBeDecryptedHere() is { } reason)
            throw new FormatException(reason);

        if (passphrase.Length == 0)
            throw new CryptographicException("incorrect passphrase");

        PrivateKeyFile file;

        try
        {
            file = new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(SshNetKeys.OpenSshPem(_blob))), passphrase);
        }
        catch (SshException ex) when (ex.Message.Contains("check bytes") || ex.Message.Contains("MAC error"))
        {
            // The format's own test of the passphrase, and for AES-GCM the tag. Told apart by
            // SSH.NET's wording: AWrongPassphrase_IsReportedAsSuch_NotAsNoMatch fails if it changes.
            throw new CryptographicException("incorrect passphrase", ex);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The key file is untrusted input, and SSH.NET reports what it cannot read with
            // whatever it hit — arithmetic errors among them.
            // Its messages can carry text from the key file, which could reach a terminal.
            throw new FormatException($"unreadable SSH private key: {Printable(ex.Message, int.MaxValue)}", ex);
        }

        using (file)
            return SshNetKeys.From(file.Key, openSshFormat: true);
    }

    private static ReadOnlySpan<byte> ReadString(ref ReadOnlySpan<byte> rest)
    {
        var length = ReadUInt32(ref rest);

        if (length > (uint)rest.Length)
            throw new FormatException("invalid OpenSSH private key: truncated");

        var value = rest[..(int)length];
        rest = rest[(int)length..];
        return value;
    }

    private static uint ReadUInt32(ref ReadOnlySpan<byte> rest)
    {
        if (rest.Length < 4)
            throw new FormatException("invalid OpenSSH private key: truncated");

        var value = BinaryPrimitives.ReadUInt32BigEndian(rest);
        rest = rest[4..];
        return value;
    }

    // The name comes from the file and ends up in an error message, possibly on a terminal.
    private static string Printable(ReadOnlySpan<byte> name) => Printable(Encoding.ASCII.GetString(name), 64);

    private static string Printable(string text, int maxLength) =>
        string.Concat(text.Take(maxLength).Select(c => c is >= ' ' and <= '~' ? c : '?'));
}
