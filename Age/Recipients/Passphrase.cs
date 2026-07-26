using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Generators;

namespace AgeSharp;

/// <summary>
///     Passphrase-based encryption via scrypt. Implements both <see cref="IRecipient" />
///     and <see cref="IIdentity" />: the same passphrase encrypts and decrypts, so pass
///     the same instance to <c>Encrypt</c> and <c>Decrypt</c>. A passphrase must be the
///     only recipient of a file (enforced on both encrypt and decrypt).
/// </summary>
/// <remarks>
///     Prefer the <see cref="Passphrase(ReadOnlySpan{char})" /> overload for long-lived
///     instances: a <see cref="string" /> cannot be zeroed by anyone, so it lingers until
///     the GC reuses the pages. The UTF-8 copy held here is zeroed by <see cref="Dispose" />.
/// </remarks>
public sealed class Passphrase : IRecipient, IIdentity
{
    private const string StanzaType = Stanza.Scrypt;
    private const string ScryptSaltLabel = "age-encryption.org/v1/scrypt";
    private const int SaltSize = 16;
    private const int MaxWorkFactor = 20;
    private const int DefaultWorkFactor = 18; // matches the age CLI
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    private readonly byte[] _passphrase;
    private readonly int _workFactor;
    private bool _disposed;

    /// <summary>Convenient, but .NET cannot zero a string — see the type's remarks.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="passphrase" /> is null.</exception>
    public Passphrase(string passphrase)
        : this(Utf8Of(passphrase), DefaultWorkFactor)
    {
    }

    /// <inheritdoc cref="Passphrase(string)" />
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="workFactor" /> is outside 1–20.</exception>
    public Passphrase(string passphrase, int workFactor)
        : this(Utf8Of(passphrase), workFactor)
    {
    }

    /// <summary>Takes characters the caller can zero afterwards; prefer this when long-lived.</summary>
    public Passphrase(ReadOnlySpan<char> passphrase)
        : this(Utf8Of(passphrase), DefaultWorkFactor)
    {
    }

    /// <inheritdoc cref="Passphrase(ReadOnlySpan{char})" />
    public Passphrase(ReadOnlySpan<char> passphrase, int workFactor)
        : this(Utf8Of(passphrase), workFactor)
    {
    }

    // Eager so a bad factor cannot overflow `1 << workFactor` or write a stanza this library
// could never read back.
    private Passphrase(byte[] utf8, int workFactor)
    {
        try
        {
            _workFactor = EnsureValidWorkFactor(workFactor);
        }
        catch
        {
            // The copy already exists by the time the factor is checked.
            CryptographicOperations.ZeroMemory(utf8);
            throw;
        }

        _passphrase = utf8;
    }

    /// <summary>Zeroes the stored passphrase bytes.</summary>
    /// <remarks>
    ///     Optional — an undisposed instance leaks only what a plain string would. It is
    ///     here so a passphrase can be cleaned up as deliberately as any other key.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_passphrase);
    }

    /// <summary>Returns null for stanzas of another type, or wrapped for a different key.</summary>
    /// <exception cref="AgeFormatException">
    ///     The stanza claims to be scrypt but is malformed, or its work factor exceeds the
    ///     maximum.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The passphrase has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        if (stanza.Type != StanzaType) return false;

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
            throw new AgeFormatException(
                $"scrypt stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var wrapKey = DeriveWrapKey(_passphrase, salt, stanzaWorkFactor);

        try
        {
            Span<byte> zeroNonce = stackalloc byte[NonceSize];
            return CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body.Span, fileKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    /// <summary>Wraps the file key under a key derived from the passphrase with a fresh salt.</summary>
    /// <exception cref="ObjectDisposedException">The passphrase has been disposed.</exception>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var wrapKey = DeriveWrapKey(_passphrase, salt, _workFactor);

        var zeroNonce = new byte[NonceSize];
        var body = CryptoHelper.ChaChaEncrypt(wrapKey, zeroNonce, fileKey);
        CryptographicOperations.ZeroMemory(wrapKey);

        var saltB64 = Base64Unpadded.Encode(salt);
        return [new Stanza(StanzaType, [saltB64, _workFactor.ToString()], body)];
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

    private static int EnsureValidWorkFactor(int workFactor)
    {
        return workFactor is >= 1 and <= MaxWorkFactor
            ? workFactor
            : throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor,
                $"scrypt work factor must be between 1 and {MaxWorkFactor}");
    }

    internal static bool ValidateWorkFactor(string s, out int workFactor)
    {
        workFactor = 0;
        if (string.IsNullOrEmpty(s))
            return false;

        // ABNF: %x31-39 *DIGIT
        if (s[0] < '1' || s[0] > '9')
            return false;

        for (var i = 1; i < s.Length; i++)
            if (s[i] < '0' || s[i] > '9')
                return false;

        return int.TryParse(s, out workFactor);
    }

    private static byte[] DeriveWrapKey(byte[] passphrase, byte[] salt, int workFactor)
    {
        var labelBytes = Encoding.ASCII.GetBytes(ScryptSaltLabel);
        var scryptSalt = (byte[])[.. labelBytes, .. salt];

        var n = 1 << workFactor;

        // The passphrase bytes belong to the instance now, so this no longer makes
        // (and zeroes) a transient UTF-8 copy on every call.
        return SCrypt.Generate(passphrase, scryptSalt, n, 8, 1, KeySize);
    }
}