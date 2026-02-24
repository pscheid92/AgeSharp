using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Format;
using NSec.Cryptography;

namespace Age.Recipients;

public sealed class ScryptRecipient : IRecipient, IIdentity
{
    private const string StanzaType = "scrypt";
    private const string ScryptSaltLabel = "age-encryption.org/v1/scrypt";
    private const int SaltSize = 16;
    private const int MaxWorkFactor = 20;

    private readonly string _passphrase;
    private readonly int _workFactor;

    public ScryptRecipient(string passphrase, int workFactor = 18)
    {
        _passphrase = passphrase;
        _workFactor = workFactor;
    }

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var wrapKey = DeriveWrapKey(_passphrase, salt, _workFactor);

        var aead = AeadAlgorithm.ChaCha20Poly1305;
        using var ck = NSec.Cryptography.Key.Import(aead, wrapKey, KeyBlobFormat.RawSymmetricKey);
        CryptographicOperations.ZeroMemory(wrapKey);

        var zeroNonce = new byte[12];
        var body = aead.Encrypt(ck, zeroNonce, ReadOnlySpan<byte>.Empty, fileKey);

        var saltB64 = Base64Unpadded.Encode(salt);
        return new Stanza(StanzaType, [saltB64, _workFactor.ToString()], body);
    }

    public byte[]? Unwrap(Stanza stanza)
    {
        if (stanza.Type != StanzaType) return null;

        if (stanza.Args.Length != 2)
            throw new AgeHeaderException($"scrypt stanza must have 2 arguments, got {stanza.Args.Length}");

        byte[] salt;
        try
        {
            salt = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"invalid scrypt salt encoding: {ex.Message}", ex);
        }

        if (salt.Length != SaltSize)
            throw new AgeHeaderException($"scrypt salt must be {SaltSize} bytes, got {salt.Length}");

        string wfStr = stanza.Args[1];
        if (!ValidateWorkFactor(wfStr, out int workFactor))
            throw new AgeHeaderException($"invalid scrypt work factor: {wfStr}");

        if (workFactor > MaxWorkFactor)
            throw new AgeHeaderException($"scrypt work factor {workFactor} exceeds maximum {MaxWorkFactor}");

        if (stanza.Body.Length != 32)
            throw new AgeHeaderException($"scrypt stanza body must be 32 bytes, got {stanza.Body.Length}");

        var wrapKey = DeriveWrapKey(_passphrase, salt, workFactor);

        var aead = AeadAlgorithm.ChaCha20Poly1305;
        using var ck = NSec.Cryptography.Key.Import(aead, wrapKey, KeyBlobFormat.RawSymmetricKey);
        CryptographicOperations.ZeroMemory(wrapKey);

        var zeroNonce = new byte[12];
        try
        {
            return aead.Decrypt(ck, zeroNonce, ReadOnlySpan<byte>.Empty, stanza.Body);
        }
        catch (CryptographicException)
        {
            throw new AgeException("incorrect passphrase for scrypt recipient");
        }
    }

    internal static bool ValidateWorkFactor(string s, out int workFactor)
    {
        workFactor = 0;
        if (string.IsNullOrEmpty(s)) return false;

        // ABNF: %x31-39 *DIGIT — first char is 1-9, rest are 0-9
        if (s[0] < '1' || s[0] > '9') return false;
        for (int i = 1; i < s.Length; i++)
        {
            if (s[i] < '0' || s[i] > '9') return false;
        }

        return int.TryParse(s, out workFactor);
    }

    private static byte[] DeriveWrapKey(string passphrase, byte[] salt, int workFactor)
    {
        // scrypt salt = "age-encryption.org/v1/scrypt" || decoded_salt (44 bytes total)
        var labelBytes = Encoding.ASCII.GetBytes(ScryptSaltLabel);
        var scryptSalt = new byte[labelBytes.Length + salt.Length];
        labelBytes.CopyTo(scryptSalt, 0);
        salt.CopyTo(scryptSalt, labelBytes.Length);

        ulong n = 1UL << workFactor;
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);

        var result = new byte[32];
        int rc = crypto_pwhash_scryptsalsa208sha256_ll(
            passphraseBytes, (nuint)passphraseBytes.Length,
            scryptSalt, (nuint)scryptSalt.Length,
            n, 8, 1,
            result, (nuint)result.Length);

        CryptographicOperations.ZeroMemory(passphraseBytes);

        if (rc != 0)
            throw new AgeException("scrypt key derivation failed");

        return result;
    }

    // P/Invoke into libsodium (bundled by NSec.Cryptography)
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_pwhash_scryptsalsa208sha256_ll(
        byte[] passwd, nuint passwdlen,
        byte[] salt, nuint saltlen,
        ulong N, uint r, uint p,
        byte[] buf, nuint buflen);
}
