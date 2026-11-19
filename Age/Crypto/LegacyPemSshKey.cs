using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO.Pem;
using Renci.SshNet;
using Renci.SshNet.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using PemReader = Org.BouncyCastle.OpenSsl.PemReader;

namespace Age.Crypto;

/// <summary>
/// A passphrase-protected ssh-rsa key in the legacy PEM format: PKCS#1 (<c>BEGIN RSA PRIVATE
/// KEY</c>) encrypted as the <c>Proc-Type: 4,ENCRYPTED</c> and <c>DEK-Info</c> headers say, as
/// ssh-keygen wrote by default before OpenSSH 7.8 and still writes with <c>-m PEM</c>.
/// </summary>
/// <remarks>
/// Nothing in the file is in the clear, the public key included, so it comes from the caller
/// (the <c>.pub</c> file), as in go-age; the decrypted key must then match it. The headers and
/// the layout of the encrypted body are checked here, before any passphrase, so that what can
/// go wrong afterwards is the passphrase. Decrypting is left to SSH.NET. Like go-age, this
/// reads PKCS#1 only: encrypted PKCS#8 is refused.
/// </remarks>
internal sealed class LegacyPemSshKey : IProtectedSshKey
{
    private const string PemType = "RSA PRIVATE KEY";

    // The ciphers SSH.NET decrypts legacy PEM keys with, and the block size of each, which is
    // also the length of its IV. go-age also reads DES-CBC; SSH.NET does not.
    private static readonly Dictionary<string, int> Ciphers = new()
    {
        ["AES-128-CBC"] = 16,
        ["AES-192-CBC"] = 16,
        ["AES-256-CBC"] = 16,
        ["DES-EDE3-CBC"] = 8,
    };

    private readonly string _cipher;
    private readonly byte[] _iv;
    private readonly byte[] _body;
    private readonly string? _whyItCannotBeDecrypted;

    private LegacyPemSshKey(string cipher, byte[] iv, byte[] body, byte[] publicKey, string? whyItCannotBeDecrypted)
    {
        _cipher = cipher;
        _iv = iv;
        _body = body;
        PublicKey = publicKey;
        _whyItCannotBeDecrypted = whyItCannotBeDecrypted;
    }

    /// <summary>The public key in SSH wire format, as the caller gave it.</summary>
    public byte[] PublicKey { get; }

    /// <summary>Whether the text is a PKCS#1 key with legacy PEM encryption headers.</summary>
    public static bool IsLegacyProtected(string pemText) =>
        pemText.Contains($"-----BEGIN {PemType}-----", StringComparison.Ordinal)
        && (pemText.Contains("Proc-Type:", StringComparison.Ordinal) || pemText.Contains("DEK-Info:", StringComparison.Ordinal));

    /// <summary>Reads the key file without decrypting it.</summary>
    /// <param name="pemText">The key file.</param>
    /// <param name="publicKey">The ssh-rsa public key the key file is for, in SSH wire format.</param>
    /// <exception cref="FormatException">
    /// The key file is malformed. A cipher that cannot be decrypted here is accepted, and
    /// refused when a file is for this key, before the passphrase is asked for.
    /// </exception>
    public static LegacyPemSshKey Parse(string pemText, byte[] publicKey)
    {
        PemObject pem;

        try
        {
            var reader = new PemReader(new StringReader(pemText));
            pem = reader.ReadPemObject() ?? throw new FormatException("invalid legacy PEM SSH key: no PEM block");

            if (reader.ReadPemObject() is not null)
                throw new FormatException("invalid legacy PEM SSH key: the file holds more than one PEM block");
        }
        catch (Exception ex) when (ex is not FormatException and not OutOfMemoryException)
        {
            // BouncyCastle reports bad base64 and broken framing with whatever it hit.
            throw new FormatException($"invalid legacy PEM SSH key: {Printable(ex.Message, int.MaxValue)}", ex);
        }

        if (pem.Type != PemType)
            throw new FormatException($"invalid legacy PEM SSH key: expected {PemType}");

        var headers = pem.Headers.Cast<PemHeader>().ToList();

        if (headers.SingleOrDefault(h => h.Name == "Proc-Type")?.Value != "4,ENCRYPTED")
            throw new FormatException("invalid legacy PEM SSH key: missing Proc-Type: 4,ENCRYPTED");

        var dekInfo = headers.SingleOrDefault(h => h.Name == "DEK-Info")?.Value
                      ?? throw new FormatException("invalid legacy PEM SSH key: missing DEK-Info");

        var comma = dekInfo.IndexOf(',');
        if (comma < 0)
            throw new FormatException("invalid legacy PEM SSH key: DEK-Info has no IV");

        var cipher = dekInfo[..comma];
        byte[] iv;

        try
        {
            iv = Convert.FromHexString(dekInfo[(comma + 1)..]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("invalid legacy PEM SSH key: the IV is not hex", ex);
        }

        var body = pem.Content;

        if (body.Length == 0)
            throw new FormatException("invalid legacy PEM SSH key: no encrypted key");

        if (!Ciphers.TryGetValue(cipher, out var blockSize))
            return new LegacyPemSshKey(cipher, iv, body, publicKey,
                $"SSH keys protected with {Printable(cipher, 64)} cannot be decrypted here; " +
                "convert the key to the OpenSSH format with ssh-keygen -p");

        if (iv.Length != blockSize)
            throw new FormatException($"invalid legacy PEM SSH key: {cipher} needs a {blockSize}-byte IV");

        if (body.Length % blockSize != 0)
            throw new FormatException($"invalid legacy PEM SSH key: the encrypted key is not whole {cipher} blocks");

        return new LegacyPemSshKey(cipher, iv, body, publicKey, whyItCannotBeDecrypted: null);
    }

    /// <inheritdoc />
    public string? WhyItCannotBeDecryptedHere() =>
        _whyItCannotBeDecrypted ?? (OperatingSystem.IsBrowser() ? WhyItCannotBeDecryptedInTheBrowser() : null);

    /// <summary>
    /// Why a legacy PEM key cannot be decrypted in the browser: it is an RSA key, and SSH.NET
    /// decrypts it with the platform's MD5, AES or 3DES and RSA, which a browser does not have.
    /// </summary>
    internal static string WhyItCannotBeDecryptedInTheBrowser() =>
        "passphrase-protected ssh-rsa keys cannot be decrypted in the browser; " +
        "use an ssh-ed25519 key protected with aes256-gcm@openssh.com";

    /// <summary>Decrypts the private key.</summary>
    /// <exception cref="CryptographicException">
    /// The passphrase is wrong, or the encrypted key is damaged: the format authenticates
    /// nothing, so the two cannot be told apart.
    /// </exception>
    /// <exception cref="FormatException">What the passphrase decrypts is not a usable ssh-rsa key.</exception>
    public (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) Unprotect(string passphrase)
    {
        if (WhyItCannotBeDecryptedHere() is { } reason)
            throw new FormatException(reason);

        if (passphrase.Length == 0)
            throw new CryptographicException("incorrect passphrase");

        PrivateKeyFile file;

        try
        {
            file = new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(Pem())), passphrase);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The headers and the block layout were checked when the file was read, so this is
            // the passphrase: the CBC padding did not come out, or (about once in 256 wrong
            // passphrases) it did and the bytes are not a key. Go's ssh package also reports
            // both as a wrong passphrase.
            throw new CryptographicException("incorrect passphrase", ex);
        }

        using (file)
        {
            return file.Key is RsaKey rsa
                ? SshKeyParser.FromRsaNumbers(Bc(rsa.Modulus), Bc(rsa.Exponent), Bc(rsa.D), Bc(rsa.P), Bc(rsa.Q), openSshFormat: false)
                : throw new CryptographicException("incorrect passphrase");
        }
    }

    // Two's complement both ways, so a negative number in the file stays negative and is refused.
    private static BcBigInteger Bc(System.Numerics.BigInteger value) =>
        new(value.ToByteArray(isUnsigned: false, isBigEndian: true));

    // Rebuilt from what was checked, rather than handing SSH.NET the caller's text.
    private string Pem() =>
        $"-----BEGIN {PemType}-----\n"
        + "Proc-Type: 4,ENCRYPTED\n"
        + $"DEK-Info: {_cipher},{Convert.ToHexString(_iv)}\n\n"
        + Convert.ToBase64String(_body, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n")
        + $"\n-----END {PemType}-----\n";

    // The cipher name comes from the file and ends up in an error message, possibly on a terminal.
    private static string Printable(string text, int maxLength) =>
        string.Concat(text.Take(maxLength).Select(c => c is >= ' ' and <= '~' ? c : '?'));
}
