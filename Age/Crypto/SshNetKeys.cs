using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Renci.SshNet;
using Renci.SshNet.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace AgeSharp.Crypto;

/// <summary>
/// Keys read by SSH.NET, turned into what the rest of AgeSharp uses and held to the same
/// checks as keys read by BouncyCastle: the public key derived from the private one, and Go's
/// checks for RSA keys.
/// </summary>
internal static class SshNetKeys
{
    /// <summary>The key type, public key and private key of what SSH.NET read.</summary>
    /// <param name="key">The key SSH.NET read.</param>
    /// <param name="openSshFormat">Whether it came from an OpenSSH key file (see <see cref="SshKeyParser.Describe"/>).</param>
    /// <exception cref="FormatException">It is not a usable ssh-ed25519 or ssh-rsa key.</exception>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) From(Key key, bool openSshFormat) => key switch
    {
        ED25519Key ed25519 => FromEd25519(ed25519),
        RsaKey rsa => SshKeyParser.FromRsaNumbers(Bc(rsa.Modulus), Bc(rsa.Exponent), Bc(rsa.D), Bc(rsa.P), Bc(rsa.Q), openSshFormat),
        _ => throw new FormatException("unsupported SSH key type: only ssh-ed25519 and ssh-rsa keys work with age"),
    };

    /// <summary>
    /// Reads an unprotected <c>openssh-key-v1</c> blob, or returns null if SSH.NET cannot.
    /// </summary>
    /// <exception cref="FormatException">SSH.NET reads it, but it is not a usable key.</exception>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey)? ReadUnprotectedOpenSsh(byte[] blob)
    {
        PrivateKeyFile file;

        try
        {
            file = new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(OpenSshPem(blob))));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Untrusted input, reported with whatever SSH.NET hit; the caller has its own error.
            return null;
        }

        using (file)
            return From(file.Key, openSshFormat: true);
    }

    /// <summary>An <c>openssh-key-v1</c> blob as the PEM text SSH.NET reads.</summary>
    public static string OpenSshPem(byte[] blob) =>
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + Convert.ToBase64String(blob, Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n")
        + "\n-----END OPENSSH PRIVATE KEY-----\n";

    // The public key is derived from the seed, not taken from the file, so a seed that is not
    // the public key's shows up as a mismatch.
    private static (string, byte[], AsymmetricKeyParameter) FromEd25519(ED25519Key key)
    {
        var seed = key.PrivateKey.ToArray();

        try
        {
            return seed.Length == Ed25519PrivateKeyParameters.KeySize
                ? SshKeyParser.Describe(new Ed25519PrivateKeyParameters(seed), openSshFormat: true)
                : throw new FormatException("invalid OpenSSH private key: malformed ssh-ed25519 key");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);

            // SSH.NET hands out the array it holds the seed in, and does not clear it itself.
            CryptographicOperations.ZeroMemory(key.PrivateKey);
        }
    }

    // Two's complement both ways, so a negative number in the file stays negative and is refused.
    private static BcBigInteger Bc(System.Numerics.BigInteger value) =>
        new(value.ToByteArray(isUnsigned: false, isBigEndian: true));
}
