using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace AgeSharp.Crypto;

internal static class SshKeyParser
{
    // age spec: SSH stanza tags use the first 4 bytes of SHA-256(publicKeyWireBytes)
    private const int FingerprintLength = 4;
    /// <summary>
    /// Parses an SSH public key from an authorized_keys line.
    /// Returns (keyType, wireBytes, publicKeyParameter).
    /// wireBytes is the raw SSH wire format bytes (the base64-decoded middle section).
    /// </summary>
    public static (string keyType, byte[] wireBytes, AsymmetricKeyParameter publicKey) ParsePublicKey(string authorizedKeysLine)
    {
        var parts = authorizedKeysLine.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new FormatException("invalid authorized_keys line: expected at least 2 fields");

        var keyType = parts[0];
        if (keyType != "ssh-ed25519" && keyType != "ssh-rsa")
            throw new FormatException($"unsupported SSH key type: {keyType}");

        byte[] wireBytes;
        try
        {
            wireBytes = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("invalid base64 in authorized_keys line", ex);
        }

        var publicKey = FromBouncyCastle(() => OpenSshPublicKeyUtilities.ParsePublicKey(wireBytes), $"invalid {keyType} public key");

        // The line names its type twice, in the first field and inside the key data. Callers
        // dispatch on the first and cast what the second produced, so they must agree.
        var dataType = KeyTypeOf(publicKey);
        if (dataType != keyType)
            throw new FormatException($"authorized_keys line says {keyType}, but its key data is {dataType ?? "another key type"}");

        if (publicKey is RsaKeyParameters rsa)
            CheckRsaPublicNumbers(rsa.Modulus, rsa.Exponent);

        return (keyType, wireBytes, publicKey);
    }

    /// <summary>
    /// Parses an SSH private key from PEM text.
    /// Returns (keyType, publicWireBytes, privateKeyParameter).
    /// Supports OpenSSH format (-----BEGIN OPENSSH PRIVATE KEY-----) and PKCS#8/PKCS#1.
    /// </summary>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) ParsePrivateKey(string pemText)
    {
        if (pemText.Contains("BEGIN OPENSSH PRIVATE KEY"))
        {
            var blob = ReadOpenSshBlob(pemText);

            if (ProtectedOpenSshKey.IsProtected(blob))
                throw PassphraseProtected();

            return ParseOpenSshBlob(blob);
        }

        object? obj;

        try
        {
            obj = FromBouncyCastle(() => new PemReader(new StringReader(pemText)).ReadObject(), "invalid PEM private key");
        }
        catch (FormatException) when (pemText.Contains("BEGIN ENCRYPTED PRIVATE KEY"))
        {
            // Encrypted PKCS#8 fails inside BouncyCastle's decoder with a message that never
            // says why.
            throw EncryptedPkcs8();
        }
        catch (FormatException ex) when (ex.InnerException is Org.BouncyCastle.OpenSsl.PasswordException)
        {
            // PKCS#1 with Proc-Type: 4,ENCRYPTED.
            throw LegacyPassphraseProtected();
        }

        return Describe(openSshFormat: false, privateKey: obj switch
        {
            AsymmetricCipherKeyPair kp => kp.Private,
            AsymmetricKeyParameter { IsPrivate: true } akp => akp,
            _ => throw new FormatException("PEM does not contain a private key")
        });
    }

    /// <summary>
    /// The passphrase-protected OpenSSH key in <paramref name="pemText"/>, or null when the text
    /// is anything else — which <see cref="ParsePrivateKey"/> then reads or refuses.
    /// </summary>
    /// <exception cref="FormatException">The key is in OpenSSH format and malformed.</exception>
    public static ProtectedOpenSshKey? ParseProtectedKey(string pemText)
    {
        // Only OpenSSH's own format stores its public key in the clear. The legacy PEM
        // encryption does not, and is read with the public key from the caller
        // (LegacyPemSshKey); ParsePrivateKey says so.
        if (!pemText.Contains("BEGIN OPENSSH PRIVATE KEY"))
            return null;

        var blob = ReadOpenSshBlob(pemText);
        return ProtectedOpenSshKey.IsProtected(blob) ? ProtectedOpenSshKey.Parse(blob) : null;
    }

    /// <summary>Parses an unprotected <c>openssh-key-v1</c> blob.</summary>
    /// <remarks>
    /// BouncyCastle reads it, or else SSH.NET, which also reads what OpenSSH and go-age accept
    /// but BouncyCastle refuses: padding longer than a block, a comment ending in a byte that
    /// looks like padding, numbers with a redundant leading zero. SSH.NET is no laxer than
    /// OpenSSH about the rest (the check values, the padding bytes, the key count), and what it
    /// reads gets the same checks, whose failure is reported as such. When SSH.NET cannot read
    /// the blob either, BouncyCastle's error is the one reported.
    /// </remarks>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) ParseOpenSshBlob(byte[] blob)
    {
        AsymmetricKeyParameter privateKey;

        try
        {
            privateKey = FromBouncyCastle(() => OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(blob), "invalid OpenSSH private key");
        }
        catch (FormatException)
        {
            if (SshNetKeys.ReadUnprotectedOpenSsh(blob) is { } readBySshNet)
                return readBySshNet;

            throw;
        }

        return Describe(privateKey, openSshFormat: true);
    }

    /// <summary>The key type named at the start of a public key in SSH wire format.</summary>
    public static string KeyTypeOfWireBytes(ReadOnlySpan<byte> wireBytes)
    {
        if (wireBytes.Length < 4 || BinaryPrimitives.ReadUInt32BigEndian(wireBytes) > (uint)wireBytes.Length - 4)
            throw new FormatException("invalid SSH public key: truncated");

        var name = wireBytes.Slice(4, (int)BinaryPrimitives.ReadUInt32BigEndian(wireBytes));
        return name.SequenceEqual("ssh-ed25519"u8) ? "ssh-ed25519"
            : name.SequenceEqual("ssh-rsa"u8) ? "ssh-rsa"
            : throw new FormatException("unsupported SSH key type: only ssh-ed25519 and ssh-rsa keys work with age");
    }

    private static byte[] ReadOpenSshBlob(string pemText)
    {
        var pemObject = FromBouncyCastle(() => new PemReader(new StringReader(pemText)).ReadPemObject(), "invalid PEM")
                        ?? throw new FormatException("failed to read PEM object");

        return pemObject.Content;
    }

    // Go's limits for RSA keys (x/crypto ssh/keys.go, parseRSA and the private-key parser): the
    // modulus OpenSSH generates at most, and a public exponent that is small, odd and at least 3.
    // With an exponent of 1, RSA-OAEP leaves the padded file key as it is, for anyone to unpad.
    private const int MaxRsaModulusBits = 16384;
    private const int MaxRsaPrimeBits = 8192;
    private const int MaxRsaExponentBits = 24;

    // The 24-bit exponent limit is the ssh package's, for public keys and OpenSSH key files; Go
    // reads PKCS#1 and PKCS#8 keys through its x509 package, which has no such limit, and
    // go-age decrypts with them. An exponent that is odd and at least 3 applies everywhere.
    private static void CheckRsaPublicNumbers(BigInteger n, BigInteger e, bool limitExponentSize = true)
    {
        if (n.BitLength > MaxRsaModulusBits)
            throw new FormatException("invalid ssh-rsa key: modulus too large");

        if (limitExponentSize && e.BitLength > MaxRsaExponentBits)
            throw new FormatException("invalid ssh-rsa key: public exponent too large");

        if (e.CompareTo(BigInteger.Three) < 0 || !e.TestBit(0))
            throw new FormatException("invalid ssh-rsa key: incorrect public exponent");
    }

    /// <summary>
    /// An RSA key from its numbers, held to the same checks as one read from a file — an
    /// OpenSSH key file or not, as <c>openSshFormat</c> says (see <see cref="Describe"/>).
    /// </summary>
    /// <exception cref="FormatException">The numbers do not make an RSA key.</exception>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) FromRsaNumbers(
        BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, bool openSshFormat) =>
        Describe(FromBouncyCastle(() => Sound(n, e, d, p, q, openSshFormat), "invalid ssh-rsa private key"), openSshFormat);

    /// <summary>The key type and public key of a parsed private key.</summary>
    /// <param name="privateKey">The private key, as BouncyCastle parsed it.</param>
    /// <param name="openSshFormat">
    /// Whether the key came from an OpenSSH key file rather than a PKCS#1 or PKCS#8 one, which
    /// decides how large an RSA public exponent may be (see <see cref="CheckRsaPublicNumbers"/>).
    /// </param>
    public static (string keyType, byte[] publicWireBytes, AsymmetricKeyParameter privateKey) Describe(AsymmetricKeyParameter privateKey, bool openSshFormat)
    {
        AsymmetricKeyParameter publicKey;
        string keyType;

        switch (privateKey)
        {
            case Ed25519PrivateKeyParameters ed25519Private:
                publicKey = ed25519Private.GeneratePublicKey();
                keyType = "ssh-ed25519";
                break;
            case RsaPrivateCrtKeyParameters rsaPrivate:
                privateKey = FromBouncyCastle(() => Sound(rsaPrivate.Modulus, rsaPrivate.PublicExponent, rsaPrivate.Exponent, rsaPrivate.P, rsaPrivate.Q, openSshFormat), "invalid ssh-rsa private key");
                publicKey = FromBouncyCastle(() => new RsaKeyParameters(false, rsaPrivate.Modulus, rsaPrivate.PublicExponent), "invalid ssh-rsa private key");
                keyType = "ssh-rsa";
                break;
            default:
                throw new FormatException($"unsupported private key type: {privateKey.GetType().Name}");
        }

        var publicWireBytes = FromBouncyCastle(() => OpenSshPublicKeyUtilities.EncodePublicKey(publicKey), "invalid SSH private key");
        return (keyType, publicWireBytes, privateKey);
    }

    /// <summary>
    /// The same RSA key once its numbers are known to belong together, with the CRT values
    /// computed from them rather than taken from the file.
    /// </summary>
    /// <remarks>
    /// A key file states the modulus, the exponents, the primes and the CRT values one by one,
    /// and nothing in the format ties them together, so a damaged or tampered file parses.
    /// BouncyCastle would decrypt with what it was given and fail, if at all, with an error of
    /// its own. As Go does (rsa.PrivateKey.Validate and Precompute) the key must satisfy
    /// n = p·q and e·d ≡ 1 modulo p−1 and q−1; and as Go and OpenSSH do, the file's own CRT
    /// values are ignored: they are redundant, and a wrong one would only be a way to fail.
    /// </remarks>
    private static RsaPrivateCrtKeyParameters Sound(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, bool openSshFormat)
    {
        var one = BigInteger.One;

        CheckRsaPublicNumbers(n, e, limitExponentSize: openSshFormat);

        // Go bounds the primes too, so a hostile key cannot make the CRT values costly to compute.
        if (p.BitLength > MaxRsaPrimeBits || q.BitLength > MaxRsaPrimeBits)
            throw new FormatException("invalid ssh-rsa private key: prime too large");

        if (p.CompareTo(one) <= 0 || q.CompareTo(one) <= 0 || d.SignValue <= 0 || !p.Multiply(q).Equals(n))
            throw new FormatException("invalid ssh-rsa private key: its parts do not belong together");

        var pMinusOne = p.Subtract(one);
        var qMinusOne = q.Subtract(one);
        var ed = e.Multiply(d);

        if (!ed.Mod(pMinusOne).Equals(one) || !ed.Mod(qMinusOne).Equals(one))
            throw new FormatException("invalid ssh-rsa private key: its parts do not belong together");

        return new RsaPrivateCrtKeyParameters(n, e, d, p, q, d.Mod(pMinusOne), d.Mod(qMinusOne), q.ModInverse(p));
    }

    private static string? KeyTypeOf(AsymmetricKeyParameter key) => key switch
    {
        Ed25519PublicKeyParameters => "ssh-ed25519",
        RsaKeyParameters { IsPrivate: false } => "ssh-rsa",
        _ => null,
    };

    private static FormatException PassphraseProtected() =>
        new("the SSH key is passphrase-protected; " +
            "parse it with a passphrase source (AgeKeygen.ParseSshIdentity(pemText, passphrase))");

    // As in go-age, which reads these given the .pub file next to the key.
    private static FormatException LegacyPassphraseProtected() =>
        new("the SSH key is passphrase-protected in the legacy PEM format, which does not store its public key; " +
            "parse it with its .pub file (AgeKeygen.ParseSshIdentity(pemText, publicKey, passphrase)), " +
            "or convert it to the OpenSSH format with ssh-keygen -p");

    // go-age does not read these either.
    private static FormatException EncryptedPkcs8() =>
        new("passphrase-protected SSH keys in encrypted PKCS#8 are not supported; " +
            "convert the key to the OpenSSH format with ssh-keygen -p");

    /// <summary>
    /// Runs a BouncyCastle parse over untrusted input and reports its failures as
    /// <see cref="FormatException"/>. BouncyCastle signals malformed keys with whatever its
    /// decoder hit — argument, range, state, arithmetic and I/O exceptions among them — and
    /// none of those may escape a parser documented to throw FormatException.
    /// </summary>
    private static T FromBouncyCastle<T>(Func<T> parse, string what)
    {
        try
        {
            return parse();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException
                                       or IndexOutOfRangeException or InvalidCastException
                                       or ArithmeticException)
        {
            throw new FormatException($"{what}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Computes the SSH key fingerprint tag used in age stanzas.
    /// tag = base64_unpadded(SHA-256(wireBytes)[:4])
    /// </summary>
    public static string ComputeTag(byte[] wireBytes)
    {
        var hash = SHA256.HashData(wireBytes);
        return Base64Unpadded.Encode(hash.AsSpan(0, FingerprintLength));
    }
}