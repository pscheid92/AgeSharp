using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Generators;

namespace AgeSharp;

/// <summary>
/// A passphrase, which encrypts a file through scrypt and decrypts it again: it is both an
/// <see cref="IRecipient"/> and an <see cref="IIdentity"/>, so the same instance goes to
/// <see cref="Recipients"/> and to <see cref="Identities"/>. A passphrase must be a file's only
/// recipient, which both encrypting and decrypting enforce.
/// </summary>
/// <remarks>
/// <para>
/// Only a UTF-8 copy of the passphrase is kept, and <see cref="Dispose"/> clears it. A
/// <see cref="string"/> cannot be cleared by anyone, so where the passphrase is held for long,
/// pass characters the caller can clear (<see cref="Passphrase(ReadOnlySpan{char})"/>).
/// </para>
/// <para>
/// Decrypting refuses a stanza whose work factor is above <see cref="MaxWorkFactor"/>: the work
/// factor is the file's to choose, so without a bound a file could demand any amount of work
/// before its passphrase is even checked.
/// </para>
/// </remarks>
public sealed class Passphrase : IRecipient, IIdentity
{
    private const string StanzaType = "scrypt";
    private const string ScryptSaltLabel = "age-encryption.org/v1/scrypt";
    private const int SaltSize = 16;
    private const int DefaultWorkFactor = 18; // the age CLI's
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag

    /// <summary>
    /// The most work a passphrase can be asked to encrypt with, and the default bound for
    /// decrypting: 22, as in go-age, about 15 seconds on a modern machine.
    /// </summary>
    private const int ReadableWorkFactor = 22;

    // The largest log2(N) for which N = 1 << workFactor still fits scrypt's parameters here.
    private const int LargestWorkFactor = 30;

    private readonly byte[] _passphrase;
    private readonly int _workFactor;
    private readonly int _maxWorkFactor = ReadableWorkFactor;
    private bool _disposed;

    /// <summary>A passphrase that encrypts with work factor 18, as the age CLI does.</summary>
    /// <remarks>The string cannot be cleared; see the remarks on the type.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="passphrase"/> is null.</exception>
    public Passphrase(string passphrase)
        : this(Utf8Of(passphrase), DefaultWorkFactor)
    {
    }

    /// <summary>A passphrase that encrypts with the given work factor.</summary>
    /// <param name="passphrase">The passphrase. The string cannot be cleared; see the remarks on the type.</param>
    /// <param name="workFactor">The scrypt cost as log2(N), 1 to 22.</param>
    /// <exception cref="ArgumentNullException"><paramref name="passphrase"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="workFactor"/> is outside 1 to 22.</exception>
    public Passphrase(string passphrase, int workFactor)
        : this(Utf8Of(passphrase), workFactor)
    {
    }

    /// <summary>
    /// A passphrase from characters the caller can clear once this returns, encrypting with work
    /// factor 18.
    /// </summary>
    public Passphrase(ReadOnlySpan<char> passphrase)
        : this(Utf8Of(passphrase), DefaultWorkFactor)
    {
    }

    /// <summary>
    /// A passphrase from characters the caller can clear once this returns, encrypting with the
    /// given work factor.
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <param name="workFactor">The scrypt cost as log2(N), 1 to 22.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="workFactor"/> is outside 1 to 22.</exception>
    public Passphrase(ReadOnlySpan<char> passphrase, int workFactor)
        : this(Utf8Of(passphrase), workFactor)
    {
    }

    // The work factor is checked here, so a bad one cannot overflow 1 << workFactor or write a
    // stanza that other readers refuse.
    private Passphrase(byte[] utf8, int workFactor)
    {
        if (workFactor is < 1 or > ReadableWorkFactor)
        {
            // The copy exists by now; it is not left behind.
            CryptographicOperations.ZeroMemory(utf8);
            throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor,
                $"scrypt work factor must be between 1 and {ReadableWorkFactor}");
        }

        _passphrase = utf8;
        _workFactor = workFactor;
    }

    /// <summary>
    /// The highest work factor a file may ask for when decrypting with this passphrase. Default:
    /// 22, as in go-age; at most 30. Raise it only for files known to have been made with more,
    /// since each step doubles the work and the memory.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is outside 1 to 30.</exception>
    public int MaxWorkFactor
    {
        get => _maxWorkFactor;
        init => _maxWorkFactor = value is >= 1 and <= LargestWorkFactor
            ? value
            : throw new ArgumentOutOfRangeException(nameof(MaxWorkFactor), value,
                $"the maximum scrypt work factor must be between 1 and {LargestWorkFactor}");
    }

    /// <summary>Wraps the file key under a key derived from the passphrase with a fresh salt.</summary>
    /// <remarks>
    /// An empty passphrase is refused here rather than at construction, as go-age refuses it: it
    /// protects nothing. It still decrypts, because earlier versions could encrypt with one.
    /// </remarks>
    /// <exception cref="ArgumentException">The passphrase is empty.</exception>
    /// <exception cref="ObjectDisposedException">The passphrase has been disposed.</exception>
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_passphrase.Length == 0)
            throw new ArgumentException("passphrase can't be empty", "passphrase");

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var wrapKey = DeriveWrapKey(salt, _workFactor);

        try
        {
            var body = CryptoHelper.ChaChaEncrypt(wrapKey, new byte[NonceSize], fileKey);
            return [new Stanza(StanzaType, [Base64Unpadded.Encode(salt), _workFactor.ToString()], body)];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    /// <summary>
    /// Unwraps the file key from an scrypt stanza: false for a stanza of another type, or one
    /// wrapped under another passphrase.
    /// </summary>
    /// <exception cref="AgeFormatException">The stanza claims to be scrypt but is malformed, or asks for more than <see cref="MaxWorkFactor"/>.</exception>
    /// <exception cref="ObjectDisposedException">The passphrase has been disposed.</exception>
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey) =>
        UnwrapInto(stanza, fileKey);

    // The file key is never in an array of ours: it is decrypted on the stack.
    private bool UnwrapInto(Stanza stanza, Span<byte> fileKey)
    {
        FileKey.RequireBuffer(fileKey);

        if (stanza.Type != StanzaType)
            return false;

        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Args.Count != 2)
            throw new AgeFormatException($"scrypt stanza must have 2 arguments, got {stanza.Args.Count}");

        byte[] salt;
        try
        {
            salt = Base64Unpadded.Decode(stanza.Args[0]);
        }
        catch (FormatException ex)
        {
            throw new AgeFormatException($"invalid scrypt salt encoding: {ex.Message}", ex);
        }

        if (salt.Length != SaltSize)
            throw new AgeFormatException($"scrypt salt must be {SaltSize} bytes, got {salt.Length}");

        var wfStr = stanza.Args[1];
        if (!ValidateWorkFactor(wfStr, out var stanzaWorkFactor))
            throw new AgeFormatException($"invalid scrypt work factor: {wfStr}");

        if (stanzaWorkFactor > _maxWorkFactor)
            throw new AgeFormatException($"scrypt work factor {stanzaWorkFactor} exceeds maximum {_maxWorkFactor}");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeFormatException($"scrypt stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var wrapKey = DeriveWrapKey(salt, stanzaWorkFactor);

        try
        {
            // An authentication failure is a different passphrase: no match.
            // On the stack, not in an array: the key reaches the caller's buffer only if it
            // authenticates, so an identity that declines leaves the buffer as it was.
            Span<byte> candidate = stackalloc byte[FileKey.Size];

            try
            {
                if (!CryptoHelper.ChaChaDecrypt(wrapKey, new byte[NonceSize], stanza.Body.Span, candidate))
                    return false;

                candidate.CopyTo(fileKey);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(candidate);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    /// <summary>Clears the passphrase. Using it afterwards throws.</summary>
    /// <remarks>
    /// Optional: an instance not disposed leaves behind no more than a string would. It is here
    /// so a passphrase can be cleaned up as deliberately as any other key.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_passphrase);
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

    private byte[] DeriveWrapKey(byte[] salt, int workFactor)
    {
        // scrypt salt = "age-encryption.org/v1/scrypt" || decoded_salt (44 bytes total)
        var scryptSalt = (byte[])[.. Encoding.ASCII.GetBytes(ScryptSaltLabel), .. salt];
        return SCrypt.Generate(_passphrase, scryptSalt, 1 << workFactor, 8, 1, KeySize);
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
}
