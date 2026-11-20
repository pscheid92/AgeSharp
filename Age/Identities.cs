using System.Collections;
using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// The identities a file may be decrypted with: the first that opens one of its stanzas wins.
/// A set is fixed once built.
/// </summary>
/// <example>
/// <code>
/// using var with = Identities.Parse(File.ReadAllText("key.txt"));
/// with.Decrypt(ciphertext, plaintext);
///
/// using var reader = new Identities(identity).DecryptReader(ciphertext);
/// </code>
/// </example>
/// <remarks>
/// <para>
/// Identities are tried in a fixed order: AgeSharp's own (X25519, ML-KEM-768-X25519, a
/// passphrase) first, then the rest, each group in the order given. As in go-age, an SSH key or
/// a plugin may ask the user for a passphrase or a touch, which it should not when one of these
/// already opens the file.
/// </para>
/// <para>
/// Disposing the set disposes the identities it parsed, clearing their keys. Identities passed
/// in stay the caller's, as the streams do: decrypting disposes neither.
/// </para>
/// </remarks>
public sealed class Identities : IReadOnlyList<IIdentity>, IDisposable
{
    private readonly IIdentity[] _members;
    private readonly IIdentity[] _tryOrder;
    private readonly bool _ownsMembers;
    private bool _disposed;

    /// <summary>A set of the given identities, which stay the caller's to dispose.</summary>
    /// <exception cref="ArgumentException">No identity was given, or one is null.</exception>
    public Identities(params ReadOnlySpan<IIdentity> identities)
        : this(identities, ownsMembers: false)
    {
    }

    /// <inheritdoc cref="Identities(ReadOnlySpan{IIdentity})"/>
    public Identities(IEnumerable<IIdentity> identities)
        : this([.. identities ?? throw new ArgumentNullException(nameof(identities))], ownsMembers: false)
    {
    }

    private Identities(ReadOnlySpan<IIdentity> identities, bool ownsMembers)
    {
        ArgumentException.ThrowIfEmpty(identities, "identity");

        foreach (var identity in identities)
        {
            if (identity is null)
                throw new ArgumentException("an identity is null", nameof(identities));
        }

        _members = identities.ToArray();
        _tryOrder = [.. _members.Where(IsNative), .. _members.Where(i => !IsNative(i))];
        _ownsMembers = ownsMembers;
    }

    private static bool IsNative(IIdentity identity) =>
        identity is X25519Identity or MlKem768X25519Identity or ScryptRecipient;

    /// <summary>The number of identities.</summary>
    public int Count => _members.Length;

    /// <summary>The identity at <paramref name="index"/>, in the order the set was built.</summary>
    public IIdentity this[int index] => _members[index];

    /// <inheritdoc/>
    public IEnumerator<IIdentity> GetEnumerator() => ((IEnumerable<IIdentity>)_members).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>
    /// Parses an identity file: one identity per line, X25519 (<c>AGE-SECRET-KEY-1…</c>),
    /// ML-KEM-768-X25519 (<c>AGE-SECRET-KEY-PQ-1…</c>) or a plugin's (<c>AGE-PLUGIN-…</c>). Empty
    /// lines and lines starting with <c>#</c> are skipped; LF and CRLF are both accepted. The set
    /// owns what it parsed, and disposing it clears the keys.
    /// </summary>
    /// <remarks>
    /// Errors name the line by number, never by content, as go-age does: a line that fails to
    /// parse is often a secret key with a stray space, and messages end up in logs.
    /// </remarks>
    /// <param name="text">The file's contents.</param>
    /// <param name="plugins">Lets plugin identities talk to the user; without it they cannot prompt.</param>
    /// <exception cref="FormatException">A line is not an identity, or the file has none.</exception>
    public static Identities Parse(string text, IPluginCallbacks? plugins = null)
    {
        ArgumentNullException.ThrowIfNull(text);

        var parsed = new List<IIdentity>();

        try
        {
            var lineNumber = 0;

            foreach (var raw in text.Split('\n'))
            {
                lineNumber++;
                var line = raw.TrimEnd('\r');

                if (line.Length == 0 || line.StartsWith('#'))
                    continue;

                parsed.Add(ParseLine(line, $"line {lineNumber} of the identity file", plugins));
            }

            if (parsed.Count == 0)
                throw new FormatException("identity file has no identities");

            return new Identities([.. parsed], ownsMembers: true);
        }
        catch
        {
            // The keys parsed before the bad line would otherwise be left uncleared.
            foreach (var identity in parsed)
                identity.Dispose();

            throw;
        }
    }

    /// <summary>
    /// Parses one identity: an identity-file line (<c>AGE-SECRET-KEY-1…</c>,
    /// <c>AGE-SECRET-KEY-PQ-1…</c>, <c>AGE-PLUGIN-…</c>) or an SSH private key in PEM that is
    /// not passphrase-protected. The caller owns, and disposes, what is returned.
    /// </summary>
    /// <param name="s">The identity's text form.</param>
    /// <param name="plugins">Lets a plugin identity talk to the user; without it, it cannot prompt.</param>
    /// <exception cref="FormatException">
    /// The text is not an identity of a known type, or it is a passphrase-protected SSH key:
    /// <see cref="AgeKeygen.ParseSshIdentity(string, Func{string})"/> reads those.
    /// </exception>
    public static IIdentity ParseOne(string s, IPluginCallbacks? plugins = null)
    {
        ArgumentNullException.ThrowIfNull(s);

        return s.TrimStart().StartsWith("-----BEGIN", StringComparison.Ordinal)
            ? AgeKeygen.ParseSshIdentity(s)
            : ParseLine(s, "identity", plugins);
    }

    private static IIdentity ParseLine(string line, string where, IPluginCallbacks? plugins)
    {
        try
        {
            if (line.StartsWith("AGE-SECRET-KEY-PQ-", StringComparison.Ordinal))
                return MlKem768X25519Identity.Parse(line);

            if (line.StartsWith("AGE-SECRET-KEY-", StringComparison.Ordinal))
                return X25519Identity.Parse(line);

            if (line.StartsWith("AGE-PLUGIN-", StringComparison.Ordinal))
                return new PluginIdentity(line, plugins);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"invalid identity ({where}): {ex.Message}", ex);
        }

        throw new FormatException(
            $"unrecognized identity ({where}): expected AGE-SECRET-KEY-1..., " +
            "AGE-SECRET-KEY-PQ-1... or AGE-PLUGIN-... with no surrounding whitespace");
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/>, binary or armored, writing the plaintext to
    /// <paramref name="plaintext"/>.
    /// </summary>
    /// <remarks>
    /// Plaintext is written as it is authenticated, a chunk at a time, so a file that fails
    /// partway leaves what came before in <paramref name="plaintext"/>. To accept all or nothing,
    /// decrypt into a buffer or a temporary file.
    /// </remarks>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeHeaderException">The header is malformed, or breaks a limit in <paramref name="options"/>.</exception>
    /// <exception cref="AgeHmacException">The header failed authentication.</exception>
    /// <exception cref="AgeArmorException">The armor is malformed, or armor is required and absent.</exception>
    /// <exception cref="AgePayloadException">The payload is malformed, truncated, or failed authentication.</exception>
    public void Decrypt(Stream ciphertext, Stream plaintext, AgeDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        using var stream = DecryptReader(ciphertext, options);
        stream.CopyTo(plaintext);
        plaintext.EnsureMaterialized();
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/>, binary or armored, into a new array: the
    /// convenience for small values.
    /// </summary>
    /// <remarks>Only the returned array holds the plaintext; the working copies are cleared.</remarks>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeException">The file is malformed or failed authentication.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, AgeDecryptOptions? options = null)
    {
        // Sized up front: the plaintext is shorter than the file, so the buffer never grows. A
        // growing MemoryStream abandons each outgrown buffer with plaintext in it.
        using var output = new MemoryStream(ciphertext.Length);

        try
        {
            Decrypt(new MemoryStream(ciphertext.ToArray()), output, options);
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output.GetBuffer());
        }
    }

    /// <summary>
    /// Decrypts asynchronously: every read of <paramref name="ciphertext"/> and write to
    /// <paramref name="plaintext"/> is asynchronous.
    /// </summary>
    /// <remarks>
    /// Unwrapping the file key happens between reading the header and the payload. For a
    /// plugin identity that is a synchronous exchange with the plugin's process, and an
    /// encrypted SSH key asks for its passphrase synchronously.
    /// </remarks>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeException">The file is malformed or failed authentication.</exception>
    public async Task DecryptAsync(Stream ciphertext, Stream plaintext, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        var stream = await DecryptReaderAsync(ciphertext, options, cancellationToken).ConfigureAwait(false);

        await using (stream.ConfigureAwait(false))
        {
            await stream.CopyToAsync(plaintext, cancellationToken).ConfigureAwait(false);
            await plaintext.EnsureMaterializedAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A stream that produces the plaintext as it is read. The header is read and authenticated,
    /// and the file key unwrapped, before this returns; the payload is decrypted a chunk at a
    /// time as it is read. Armor is detected on any readable stream. Dispose it when done; that
    /// leaves <paramref name="ciphertext"/> open.
    /// </summary>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeException">The header or armor is malformed, or the header failed authentication.</exception>
    public Stream DecryptReader(Stream ciphertext, AgeDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ObjectDisposedException.ThrowIf(_disposed, this);
        options ??= AgeDecryptOptions.Default;

        // The binary input is ours (a look-ahead or a dearmoring wrapper, neither of which
        // disposes the caller's stream). The returned DecryptStream takes it over; until then a
        // failure disposes it here.
        var (binary, _) = AsciiArmor.Open(ciphertext, options);

        try
        {
            var reader = new HeaderReader(binary, options);

            using var fileKey = Unlock(ParseHeader(reader));

            var nonce = new byte[StreamEncryption.PayloadNonceSize];
            return new DecryptStream(PayloadKey(fileKey, nonce, reader.ReadPayloadBytes(nonce)), binary, ownsStream: true);
        }
        catch
        {
            binary.Dispose();
            throw;
        }
    }

    /// <summary>The asynchronous <see cref="DecryptReader"/>: the header is read asynchronously too.</summary>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeException">The header or armor is malformed, or the header failed authentication.</exception>
    public async ValueTask<Stream> DecryptReaderAsync(Stream ciphertext, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ObjectDisposedException.ThrowIf(_disposed, this);
        options ??= AgeDecryptOptions.Default;

        var (binary, _) = await AsciiArmor.OpenAsync(ciphertext, options, cancellationToken).ConfigureAwait(false);

        try
        {
            var reader = new HeaderReader(binary, options);
            await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);

            var nonce = new byte[StreamEncryption.PayloadNonceSize];
            byte[] payloadKey;

            // The file key is cleared before the nonce is awaited, so no continuation holds it;
            // the payload key it derives is needed only once the nonce is in.
            var header = ParseHeader(reader);
            var nonceRead = await reader.ReadPayloadBytesAsync(nonce, cancellationToken).ConfigureAwait(false);

            using (var fileKey = Unlock(header))
                payloadKey = PayloadKey(fileKey, nonce, nonceRead);

            return new DecryptStream(payloadKey, binary, ownsStream: true);
        }
        catch
        {
            await binary.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// A stream that decrypts the age file written to it, binary or armored, writing the
    /// plaintext to <paramref name="plaintext"/> a chunk at a time as each authenticates, in the
    /// manner of <c>GZipStream</c>. Creating it reads nothing; the header is parsed and the file
    /// key unwrapped once enough of the file has been written. Writes may be synchronous or
    /// asynchronous; use <c>await using</c> to finish asynchronously too.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only disposing says the file has ended, so that is where the last chunk is decrypted and
    /// where a truncated or malformed ending throws. Dispose it explicitly, or with
    /// <c>using</c>, and expect it to throw. Until it has returned, the plaintext written so far
    /// is unconfirmed: a file cut short is found out only at its end.
    /// </para>
    /// <para>
    /// Once a write has thrown, every later write throws the same exception and disposing
    /// finishes nothing and throws nothing more. <paramref name="plaintext"/> stays open.
    /// </para>
    /// </remarks>
    public Stream DecryptWriter(Stream plaintext, AgeDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ObjectDisposedException.ThrowIf(_disposed, this);

        return new DecryptWriterStream(plaintext, this, options ?? AgeDecryptOptions.Default);
    }

    /// <summary>
    /// Decrypts a file whose header and payload are kept apart, the inverse of
    /// <see cref="Recipients.EncryptDetached"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="options"/> requires armor, which a detached header never has.</exception>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeException">The header or payload is malformed, or failed authentication.</exception>
    public void DecryptDetached(Stream header, Stream payload, Stream plaintext, AgeDecryptOptions? options = null)
    {
        options = DetachedOptions(header, payload, plaintext, options);

        var reader = new HeaderReader(header, options);
        using var fileKey = Unlock(ParseHeader(reader));

        var nonce = new byte[StreamEncryption.PayloadNonceSize];
        var nonceRead = payload.ReadAtLeast(nonce, nonce.Length, throwOnEndOfStream: false);

        using var stream = new DecryptStream(PayloadKey(fileKey, nonce, nonceRead), payload, ownsStream: false);
        stream.CopyTo(plaintext);
        plaintext.EnsureMaterialized();
    }

    /// <summary>The asynchronous <see cref="DecryptDetached"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="options"/> requires armor, which a detached header never has.</exception>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeException">The header or payload is malformed, or failed authentication.</exception>
    public async Task DecryptDetachedAsync(Stream header, Stream payload, Stream plaintext, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        options = DetachedOptions(header, payload, plaintext, options);

        var reader = new HeaderReader(header, options);
        await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);
        var parsed = ParseHeader(reader);

        var nonce = new byte[StreamEncryption.PayloadNonceSize];
        var nonceRead = await payload.ReadAtLeastAsync(nonce, nonce.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);

        byte[] payloadKey;
        using (var fileKey = Unlock(parsed))
            payloadKey = PayloadKey(fileKey, nonce, nonceRead);

        var stream = new DecryptStream(payloadKey, payload, ownsStream: false);

        await using (stream.ConfigureAwait(false))
        {
            await stream.CopyToAsync(plaintext, cancellationToken).ConfigureAwait(false);
            await plaintext.EnsureMaterializedAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private AgeDecryptOptions DetachedOptions(Stream header, Stream payload, Stream plaintext, AgeDecryptOptions? options)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(plaintext);
        ObjectDisposedException.ThrowIf(_disposed, this);

        options ??= AgeDecryptOptions.Default;

        return options.RequireArmor
            ? throw new ArgumentException("a detached header is never armored, so armor cannot be required", nameof(options))
            : options;
    }

    /// <summary>Disposes the identities the set parsed; identities passed in are left alone.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        if (_ownsMembers)
        {
            foreach (var identity in _members)
                identity.Dispose();
        }
    }

    /// <summary>
    /// The file key, from the first identity in the trying order that opens a stanza, with the
    /// header's MAC verified under it.
    /// </summary>
    /// <exception cref="NoIdentityMatchException">No identity opened any stanza.</exception>
    /// <exception cref="AgeHmacException">The header failed authentication.</exception>
    internal FileKey Unlock(Header header) => Unlock(header, _tryOrder);

    /// <inheritdoc cref="Unlock(Header)"/>
    internal static FileKey Unlock(Header header, IIdentity[] tryOrder)
    {
        if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
            throw new AgeHeaderException("scrypt stanza must be the only stanza in the header");

        var owned = FileKey.UnwrapFrom(header.Stanzas, tryOrder) ?? throw new NoIdentityMatchException();

        // From here a throw disposes the key rather than abandons it. VerifyMac failing is
        // routine: a tampered or corrupted header.
        try
        {
            header.VerifyMac(owned.Bytes);
            return owned;
        }
        catch
        {
            owned.Dispose();
            throw;
        }
    }

    /// <summary>The identities in the order they are tried; see the remarks on <see cref="Identities"/>.</summary>
    internal static IIdentity[] TryOrder(ReadOnlySpan<IIdentity> identities) =>
        new Identities(identities)._tryOrder;

    /// <summary>The payload key, from the file key and the payload nonce, once all of it was read.</summary>
    internal static byte[] PayloadKey(FileKey fileKey, byte[] nonce, int nonceRead) =>
        nonceRead == nonce.Length
            ? CryptoHelper.HkdfDerive(fileKey.Bytes, nonce, "payload", StreamEncryption.PayloadKeySize)
            : throw new AgeHeaderException($"expected {nonce.Length}-byte payload nonce, got {nonceRead} bytes");

    internal static Header ParseHeader(HeaderReader reader)
    {
        try
        {
            return Header.Parse(reader);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"header parse error: {ex.Message}", ex);
        }
    }
}
