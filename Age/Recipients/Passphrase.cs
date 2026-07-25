using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Generators;

namespace AgeSharp;

/// <summary>
/// Passphrase-based encryption via scrypt. Implements both <see cref="IRecipient"/>
/// and <see cref="IIdentity"/>: the same passphrase encrypts and decrypts, so pass
/// the same instance to <c>Encrypt</c> and <c>Decrypt</c>. A passphrase must be the
/// only recipient of a file (enforced on both encrypt and decrypt).
/// </summary>
/// <remarks>
/// The passphrase is held as a UTF-8 byte copy that <see cref="Dispose"/> zeroes,
/// matching how every other secret-holding type in the library behaves. Prefer the
/// <see cref="Passphrase(ReadOnlySpan{char})"/> overload for long-lived
/// instances: a <see cref="string"/> argument cannot be zeroed by this class or by
/// anyone else, so it stays in memory until the GC happens to reuse the pages.
/// </remarks>
public sealed class Passphrase : IRecipient, IIdentity
{
    private const string StanzaType = "scrypt";
    private const string ScryptSaltLabel = "age-encryption.org/v1/scrypt";
    private const int SaltSize = 16;
    private const int MaxWorkFactor = 20;
    private const int DefaultWorkFactor = 18; // matches the age CLI
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    // UTF-8 rather than the original string, so it can actually be zeroed.
    private readonly byte[] _passphrase;
    private readonly int _workFactor;
    private bool _disposed;

    /// <summary>
    /// Creates a passphrase from a <see cref="string"/>. Convenient, but .NET cannot
    /// zero a string — see the <see cref="Passphrase"/> remarks.
    /// </summary>
    /// <param name="passphrase">The passphrase; used as UTF-8 bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="passphrase"/> is null.</exception>
    public Passphrase(string passphrase)
        : this(Utf8Of(passphrase), DefaultWorkFactor)
    {
    }

    /// <inheritdoc cref="Passphrase(string)"/>
    /// <param name="passphrase">The passphrase; used as UTF-8 bytes.</param>
    /// <param name="workFactor">
    /// The scrypt cost as log2(N), 1–20 (18 when not given, matching the age CLI).
    /// Decryption refuses stanzas whose work factor exceeds 20.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="workFactor"/> is outside 1–20.</exception>
    public Passphrase(string passphrase, int workFactor)
        : this(Utf8Of(passphrase), workFactor)
    {
    }

    /// <summary>
    /// Creates a passphrase from characters the caller can zero afterwards — the
    /// overload to prefer when the instance is long-lived.
    /// </summary>
    /// <param name="passphrase">The passphrase; copied as UTF-8 bytes.</param>
    public Passphrase(ReadOnlySpan<char> passphrase)
        : this(Utf8Of(passphrase), DefaultWorkFactor)
    {
    }

    /// <inheritdoc cref="Passphrase(ReadOnlySpan{char})"/>
    /// <param name="passphrase">The passphrase; copied as UTF-8 bytes.</param>
    /// <param name="workFactor">The scrypt cost as log2(N), 1–20.</param>
    public Passphrase(ReadOnlySpan<char> passphrase, int workFactor)
        : this(Utf8Of(passphrase), workFactor)
    {
    }

    // Validate eagerly so an out-of-range work factor fails at construction
    // rather than overflowing `1 << workFactor` or producing a stanza this
    // library (which caps decryption at MaxWorkFactor) could never read back.
    private Passphrase(byte[] utf8, int workFactor)
    {
        try
        {
            _workFactor = EnsureValidWorkFactor(workFactor);
        }
        catch
        {
            // The UTF-8 copy already exists by the time the work factor is checked,
            // so a rejected one must not leave the passphrase sitting in memory.
            CryptographicOperations.ZeroMemory(utf8);
            throw;
        }

        _passphrase = utf8;
    }

    private static byte[] Utf8Of(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        return Encoding.UTF8.GetBytes(passphrase);
    }

    private static byte[] Utf8Of(ReadOnlySpan<char> passphrase)
    {
        var bytes = new byte[Encoding.UTF8.GetByteCount(passphrase)];
        Encoding.UTF8.GetBytes(passphrase, bytes);
        return bytes;
    }

    /// <summary>Zeroes the stored passphrase bytes.</summary>
    /// <remarks>
    /// Optional — an undisposed instance leaks only what a plain string would. It is
    /// here so a passphrase can be cleaned up as deliberately as any other key.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_passphrase);
    }

    private static int EnsureValidWorkFactor(int workFactor) =>
        workFactor is >= 1 and <= MaxWorkFactor
            ? workFactor
            : throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor,
                $"scrypt work factor must be between 1 and {MaxWorkFactor}");

    /// <summary>Wraps the file key under a key derived from the passphrase with a fresh salt.</summary>
    /// <exception cref="ObjectDisposedException">The passphrase has been disposed.</exception>
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var wrapKey = DeriveWrapKey(_passphrase, salt, _workFactor);

        var zeroNonce = new byte[NonceSize];
        var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
        CryptographicOperations.ZeroMemory(wrapKey);

        var saltB64 = Base64Unpadded.Encode(salt);
        return new Stanza(StanzaType, [saltB64, _workFactor.ToString()], body);
    }

    /// <summary>
    /// Attempts to unwrap the file key from an scrypt stanza. Returns null for
    /// stanzas of other types or when the passphrase is wrong.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza claims to be scrypt but is malformed, or its work factor exceeds the maximum.</exception>
    /// <exception cref="ObjectDisposedException">The passphrase has been disposed.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        if (stanza.Type != StanzaType) return null;

        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Args.Count != 2)
            throw new AgeFormatException($"scrypt stanza must have 2 arguments, got {stanza.Args.Count}");

        var salt = ParseHelpers.DecodeArg(stanza.Args[0], SaltSize, "scrypt salt");

        var wfStr = stanza.Args[1];
        if (!ValidateWorkFactor(wfStr, out var stanzaWorkFactor))
            throw new AgeFormatException($"invalid scrypt work factor: {wfStr}");

        if (stanzaWorkFactor > MaxWorkFactor)
            throw new AgeFormatException($"scrypt work factor {stanzaWorkFactor} exceeds maximum {MaxWorkFactor}");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeFormatException($"scrypt stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var wrapKey = DeriveWrapKey(_passphrase, salt, stanzaWorkFactor);

        var zeroNonce = new byte[NonceSize];
        var fileKey = CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body.Span);
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

    private static byte[] DeriveWrapKey(byte[] passphrase, byte[] salt, int workFactor)
    {
        // scrypt salt = "age-encryption.org/v1/scrypt" || decoded_salt (44 bytes total)
        var labelBytes = Encoding.ASCII.GetBytes(ScryptSaltLabel);
        var scryptSalt = (byte[])[.. labelBytes, .. salt];

        var n = 1 << workFactor;

        // The passphrase bytes belong to the instance now, so this no longer makes
        // (and zeroes) a transient UTF-8 copy on every call.
        return SCrypt.Generate(passphrase, scryptSalt, n, 8, 1, KeySize);
    }
}