using System.Security.Cryptography;
using System.Text;
using Age.Crypto;
using Age.Format;
using Org.BouncyCastle.Crypto.Generators;

namespace Age.Recipients;

public sealed class ScryptRecipient(string passphrase, int workFactor = 18) : IRecipient, IIdentity
{
    private const string StanzaType = "scrypt";
    private const string ScryptSaltLabel = "age-encryption.org/v1/scrypt";
    private const int SaltSize = 16;
    private const int MaxWorkFactor = 20;
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var wrapKey = DeriveWrapKey(passphrase, salt, workFactor);

        var zeroNonce = new byte[NonceSize];
        var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
        CryptographicOperations.ZeroMemory(wrapKey);

        var saltB64 = Base64Unpadded.Encode(salt);
        return new Stanza(StanzaType, [saltB64, workFactor.ToString()], body);
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

        var wfStr = stanza.Args[1];
        if (!ValidateWorkFactor(wfStr, out var stanzaWorkFactor))
            throw new AgeHeaderException($"invalid scrypt work factor: {wfStr}");

        if (stanzaWorkFactor > MaxWorkFactor)
            throw new AgeHeaderException($"scrypt work factor {stanzaWorkFactor} exceeds maximum {MaxWorkFactor}");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeHeaderException($"scrypt stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var wrapKey = DeriveWrapKey(passphrase, salt, stanzaWorkFactor);

        var zeroNonce = new byte[NonceSize];
        var fileKey = CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body);
        CryptographicOperations.ZeroMemory(wrapKey);

        // AEAD auth failure → wrong passphrase, return null to signal no match
        return fileKey;
    }

    internal static bool ValidateWorkFactor(string s, out int workFactor)
    {
        workFactor = 0;
        if (string.IsNullOrEmpty(s))
            return false;

        // ABNF: %x31-39 *DIGIT — first char is 1-9, rest are 0-9
        if (s[0] < '1' || s[0] > '9')
            return false;

        for (var i = 1; i < s.Length; i++)
        {
            if (s[i] < '0' || s[i] > '9')
                return false;
        }

        return int.TryParse(s, out workFactor);
    }

    private static byte[] DeriveWrapKey(string passphrase, byte[] salt, int workFactor)
    {
        // scrypt salt = "age-encryption.org/v1/scrypt" || decoded_salt (44 bytes total)
        var labelBytes = Encoding.ASCII.GetBytes(ScryptSaltLabel);
        var scryptSalt = (byte[])[.. labelBytes, .. salt];

        var n = 1 << workFactor;
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);

        var result = SCrypt.Generate(passphraseBytes, scryptSalt, n, 8, 1, KeySize);

        CryptographicOperations.ZeroMemory(passphraseBytes);

        return result;
    }
}