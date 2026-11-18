using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

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
internal sealed class ProtectedOpenSshKey
{
    // bcrypt_pbkdf costs time linear in the round count, and the count comes from the file:
    // OpenSSH sets no upper bound, and neither does SSH.NET. 2048 is the bound Go's ssh
    // package, and so go-age, applies — some fifteen seconds of work on a current laptop, not
    // the months a hostile file could ask for.
    private const uint MaxRounds = 1 << 11;

    private static ReadOnlySpan<byte> Magic => "openssh-key-v1\0"u8;

    private readonly byte[] _blob;
    private readonly string _cipher;

    private ProtectedOpenSshKey(byte[] blob, string cipher, byte[] publicKey)
    {
        _blob = blob;
        _cipher = cipher;
        PublicKey = publicKey;
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
    /// <exception cref="FormatException">
    /// The blob is malformed, is not passphrase-protected, or uses a KDF this library does not
    /// read or more bcrypt rounds than it will spend.
    /// </exception>
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

        if (!kdfName.SequenceEqual("bcrypt"u8))
            throw new FormatException($"unsupported SSH private key KDF: {Printable(kdfName)}");

        if (keyCount != 1)
            throw new FormatException($"an OpenSSH private key file must hold exactly one key, got {keyCount}");

        var salt = ReadString(ref kdfOptions);
        var rounds = ReadUInt32(ref kdfOptions);

        if (salt.IsEmpty || rounds == 0 || !kdfOptions.IsEmpty)
            throw new FormatException("invalid OpenSSH private key: malformed bcrypt options");

        if (rounds > MaxRounds)
            throw new FormatException($"SSH private key asks for {rounds} bcrypt rounds, more than the maximum of {MaxRounds}");

        return new ProtectedOpenSshKey(blob.ToArray(), Printable(cipherName), publicKey.ToArray());
    }

    /// <summary>
    /// Why this key cannot be decrypted on this platform, or null if it can. Asked before the
    /// passphrase is, so nobody types one that cannot be used.
    /// </summary>
    public string? WhyItCannotBeDecryptedHere() =>
        OperatingSystem.IsBrowser() ? WhyItCannotBeDecryptedInTheBrowser(SshKeyParser.KeyTypeOfWireBytes(PublicKey), _cipher) : null;

    /// <summary>
    /// Why a protected key of this type and cipher cannot be decrypted in the browser, or null
    /// if it can.
    /// </summary>
    /// <remarks>
    /// SSH.NET builds every RSA key it decrypts as a platform RSA object, which a browser does
    /// not have, whatever the cipher. It decrypts AES-CTR and AES-CBC with the platform's AES,
    /// which a browser does not have either; its AES-GCM and ChaCha20-Poly1305 are
    /// BouncyCastle's and run anywhere. AES-CTR is what ssh-keygen protects keys with by default.
    /// </remarks>
    internal static string? WhyItCannotBeDecryptedInTheBrowser(string keyType, string cipher)
    {
        if (keyType == "ssh-rsa")
            return "passphrase-protected ssh-rsa keys cannot be decrypted in the browser; " +
                   "use an ssh-ed25519 key protected with aes256-gcm@openssh.com";

        if (cipher.StartsWith("aes", StringComparison.Ordinal) && !cipher.Contains("gcm", StringComparison.Ordinal))
            return $"SSH keys protected with {cipher} cannot be decrypted in the browser; " +
                   "re-protect a copy with ssh-keygen -p -Z aes256-gcm@openssh.com";

        return null;
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
        if (passphrase.Length == 0)
            throw new CryptographicException("incorrect passphrase");

        PrivateKeyFile file;

        try
        {
            file = new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(Pem())), passphrase);
        }
        catch (SshException ex) when (ex.Message.Contains("check bytes") || ex.Message.Contains("MAC error"))
        {
            // The format's own test of the passphrase, and for AES-GCM the tag.
            throw new CryptographicException("incorrect passphrase", ex);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The key file is untrusted input, and SSH.NET reports what it cannot read with
            // whatever it hit — arithmetic errors among them.
            throw new FormatException($"unreadable SSH private key: {ex.Message}", ex);
        }

        using (file)
        {
            return file.Key switch
            {
                ED25519Key ed25519 => FromEd25519(ed25519),
                RsaKey rsa => SshKeyParser.FromRsaNumbers(Bc(rsa.Modulus), Bc(rsa.Exponent), Bc(rsa.D), Bc(rsa.P), Bc(rsa.Q)),
                _ => throw new FormatException("unsupported SSH key type: only ssh-ed25519 and ssh-rsa keys work with age"),
            };
        }
    }

    // The public key is derived from the seed, not taken from the file, so a seed that is not
    // the public key's shows up as a mismatch.
    private static (string, byte[], AsymmetricKeyParameter) FromEd25519(ED25519Key key)
    {
        var seed = key.PrivateKey.ToArray();

        try
        {
            return seed.Length == Ed25519PrivateKeyParameters.KeySize
                ? SshKeyParser.Describe(new Ed25519PrivateKeyParameters(seed))
                : throw new FormatException("invalid OpenSSH private key: malformed ssh-ed25519 key");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    // Two's complement both ways, so a negative number in the file stays negative and is refused.
    private static BcBigInteger Bc(System.Numerics.BigInteger value) =>
        new(value.ToByteArray(isUnsigned: false, isBigEndian: true));

    private string Pem() =>
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + Convert.ToBase64String(_blob, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n")
        + "\n-----END OPENSSH PRIVATE KEY-----\n";

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
    private static string Printable(ReadOnlySpan<byte> name) =>
        string.Concat(Encoding.ASCII.GetString(name).Take(64).Select(c => c is >= ' ' and <= '~' ? c : '?'));
}
