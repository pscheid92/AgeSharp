using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
///     Top-level entry point for encrypting and decrypting data in the age format.
///     All streaming APIs are memory-bounded: a 1 GiB input uses the same working
///     set as a 1 MB input (two 64 KiB chunk buffers rented from <c>ArrayPool</c>).
///     This holds for ASCII-armored input too — armor is decoded a line at a time
///     rather than buffered — and on the asynchronous paths as well as the
///     synchronous ones.
/// </summary>
/// <remarks>
///     <para>
///         Four members return a <see cref="Stream" />, one per combination of which
///         operation runs and which side drives it:
///     </para>
///     <list type="table">
///         <listheader>
///             <term /><description>you read | you write</description>
///         </listheader>
///         <item>
///             <term>encrypt</term>
///             <description>
///                 <see cref="EncryptReader" /> |
///                 <see cref="EncryptWriter" />
///             </description>
///         </item>
///         <item>
///             <term>decrypt</term>
///             <description>
///                 <see cref="DecryptReader" /> |
///                 <see cref="DecryptWriter" />
///             </description>
///         </item>
///     </list>
///     <para>
///         The <c>*Reader</c> pair is pull — you drive by reading, and setup is eager. The
///         <c>*Writer</c> pair is push, in the spirit of
///         <see cref="System.IO.Compression.GZipStream" />, and disposing them finalizes the
///         transfer. <see cref="DecryptWriter" />
///         is the one member that cannot set up eagerly, since nothing is known about the
///         file until bytes arrive; its own documentation covers what that changes.
///     </para>
///     <para>
///         Recipients and identities are always passed as an <see cref="IReadOnlyList{T}" />,
///         and options always come last as an optional argument. One shape, everywhere —
///         including the asynchronous members, which differ only by a trailing
///         <see cref="CancellationToken" />. At a call site that usually means a collection
///         expression: <c>Age.Encrypt(input, output, [recipient])</c>. An empty list is an
///         <see cref="ArgumentException" />, checked at runtime.
///     </para>
/// </remarks>
public static partial class Age
{
    private const int FileKeySize = 16;
    internal const int PayloadNonceSize = 16;
    internal const int PayloadKeySize = 32;

    /// <summary>
    ///     Encrypts <paramref name="input" /> into age format and writes the result to
    ///     <paramref name="output" />.
    /// </summary>
    /// <param name="input">The plaintext source. Read once, start to end.</param>
    /// <param name="output">The ciphertext destination.</param>
    /// <param name="recipients">
    ///     One or more recipients. A collection expression is the usual form:
    ///     <c>[recipient]</c>, or <c>[alice, bob]</c>. All must produce the same label
    ///     set (see <see cref="IRecipientWithLabels" />).
    /// </param>
    /// <param name="options">
    ///     Encryption options; <see cref="AgeEncryptOptions.Armor" /> selects armored
    ///     output. Defaults are used when null.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    /// <exception cref="AgeException">
    ///     Recipients have mismatched security labels, or a passphrase (scrypt)
    ///     recipient was combined with other recipients.
    /// </exception>
    public static void Encrypt(Stream input, Stream output, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        using var stream = EncryptReader(input, recipients, options);
        stream.CopyTo(output);
    }

    /// <summary>
    ///     Decrypts an age-encrypted <paramref name="input" /> into <paramref name="output" />.
    ///     Armored input is auto-detected on any stream, seekable or not.
    /// </summary>
    /// <param name="input">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="identities">
    ///     One or more identities, tried against the file's recipient stanzas until one
    ///     unwraps the file key.
    /// </param>
    /// <param name="options">
    ///     Parsing options (armor strictness and the header-size limits); defaults are
    ///     used when null.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC failed, or the payload is malformed or truncated.</exception>
    public static void Decrypt(Stream input, Stream output, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        using var stream = DecryptReader(input, identities, options);
        stream.CopyTo(output);
        // Ensure output is touched even when plaintext is empty — matters for
        // lazy-creating writers that only materialize on first Write.
        output.Write(ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    ///     Encrypts <paramref name="plaintext" /> and returns the age ciphertext as a
    ///     new byte array. A buffer-in, buffer-out convenience for small payloads
    ///     (secrets, database fields) that skips the <see cref="MemoryStream" /> ceremony.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt. Copied, then zeroed after use.</param>
    /// <param name="recipients">One or more recipients, e.g. <c>[recipient]</c>.</param>
    /// <param name="options">Encryption options; defaults are used when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        // Copy into an owned buffer so the plaintext can be zeroed afterwards; the
        // returned ciphertext is not secret.
        var buffer = plaintext.ToArray();
        try
        {
            using var input = new MemoryStream(buffer);
            using var output = new MemoryStream();
            Encrypt(input, output, recipients, options);
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    ///     Decrypts age <paramref name="ciphertext" /> and returns the plaintext as a
    ///     new byte array — the buffer-in, buffer-out counterpart to
    ///     <see cref="Encrypt(ReadOnlySpan{byte}, IReadOnlyList{IRecipient}, AgeEncryptOptions)" />.
    ///     Armored input is auto-detected.
    /// </summary>
    /// <param name="ciphertext">The age ciphertext (binary or ASCII-armored).</param>
    /// <param name="identities">One or more identities, e.g. <c>[identity]</c>.</param>
    /// <param name="options">Parsing options; defaults are used when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header or armor is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">The header MAC or a payload chunk failed authentication.</exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        using var input = new MemoryStream(ciphertext.ToArray());
        using var output = new MemoryStream();

        try
        {
            Decrypt(input, output, identities, options);
            return output.ToArray();
        }
        finally
        {
            // The returned array is the caller's copy; this one is ours to clear.
            // Disposing a MemoryStream does not touch its buffer, so without this a
            // second copy of the plaintext would outlive the call. Also runs when
            // decryption throws partway, since the buffer holds plaintext by then.
            CryptographicOperations.ZeroMemory(output.GetBuffer());
        }
    }

    /// <summary>
    ///     Encrypts <paramref name="input" />, writing the age header to
    ///     <paramref name="headerOutput" /> and the encrypted payload to
    ///     <paramref name="payloadOutput" />. Useful when header and payload
    ///     need to live in separate locations (e.g. a metadata store and a
    ///     blob store).
    /// </summary>
    /// <remarks>
    ///     The one entry point with no options parameter, and deliberately so: ASCII armor
    ///     is a container around a whole age file, which a detached header and payload are
    ///     not, so there is nothing <see cref="AgeEncryptOptions" /> could configure here.
    ///     <see cref="DecryptDetached" /> does take options, because it parses a header.
    /// </remarks>
    /// <param name="input">The plaintext source.</param>
    /// <param name="headerOutput">The destination for the age header.</param>
    /// <param name="payloadOutput">The destination for the encrypted payload.</param>
    /// <param name="recipients">One or more recipients, e.g. <c>[recipient]</c>. Must all produce the same label set.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static void EncryptDetached(Stream input, Stream headerOutput, Stream payloadOutput, IReadOnlyList<IRecipient> recipients)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));
        try
        {
            header.WriteTo(headerOutput, fileKey);

            var payloadNonce = new byte[PayloadNonceSize];
            RandomNumberGenerator.Fill(payloadNonce);
            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);

            using var payloadStream = new EncryptStream([], payloadNonce, payloadKey, input);
            payloadStream.CopyTo(payloadOutput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    ///     Decrypts an age file whose header and payload are stored separately —
    ///     the inverse of <see cref="EncryptDetached" />.
    /// </summary>
    /// <param name="headerInput">The detached age header.</param>
    /// <param name="payloadInput">The detached encrypted payload.</param>
    /// <param name="output">The plaintext destination.</param>
    /// <param name="identities">One or more identities tried against the header's recipient stanzas.</param>
    /// <param name="options">Parsing options (the header-size limits); defaults are used when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        var fileKey = UnwrapFileKey(headerInput, Materialize(identities, nameof(identities), "identity"), options ?? AgeDecryptOptions.Default);
        try
        {
            var payloadNonce = new byte[PayloadNonceSize];
            var total = 0;

            while (total < PayloadNonceSize)
            {
                var read = payloadInput.Read(payloadNonce.AsSpan(total));
                if (read == 0)
                    break;

                total += read;
            }

            if (total != PayloadNonceSize)
                throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {total} bytes");

            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);

            using var decryptStream = new DecryptStream(payloadKey, payloadInput, false);
            decryptStream.CopyTo(output);
            // Ensure output is touched even when plaintext is empty — matters for
            // lazy-creating writers that only materialize on first Write.
            output.Write(ReadOnlySpan<byte>.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    ///     Returns a readable <see cref="Stream" /> that produces age ciphertext
    ///     as the caller reads from it. Header setup and key derivation happen
    ///     eagerly; payload encryption is lazy (chunk-by-chunk on <c>Read()</c>).
    ///     Dispose the returned stream when done.
    /// </summary>
    /// <param name="plaintext">The plaintext source.</param>
    /// <param name="recipients">One or more recipients, e.g. <c>[recipient]</c>.</param>
    /// <param name="options">Encryption options; <see cref="AgeEncryptOptions.Armor" /> selects armored output. Defaults when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static Stream EncryptReader(Stream plaintext, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        var recipientArray = Materialize(recipients, nameof(recipients), "recipient");

        if (options?.Armor == true)
        {
            var ciphertextStream = EncryptReader(plaintext, recipientArray);
            return new ArmorStream(ciphertextStream);
        }

        var (header, fileKey) = BuildHeaderAndFileKey(recipientArray);

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        CryptographicOperations.ZeroMemory(fileKey);

        return new EncryptStream(headerBytes, payloadNonce, payloadKey, plaintext);
    }

    /// <summary>
    ///     Returns a writable <see cref="Stream" /> that encrypts the plaintext written
    ///     to it and forwards age ciphertext to <paramref name="destination" />
    ///     (<see cref="System.IO.Compression.GZipStream" />-style push encryption).
    ///     Recipient wrapping and the label/scrypt checks run eagerly; the header write
    ///     is deferred to the first write (or to <c>Dispose</c> when nothing is written,
    ///     which produces a valid empty-plaintext file). Disposing the returned stream
    ///     finalizes the age payload; <paramref name="destination" /> is never disposed.
    /// </summary>
    /// <remarks>
    ///     <c>Flush</c> flushes <paramref name="destination" /> but cannot flush a partial
    ///     age chunk: STREAM chunks are fixed size, and a short one marks the end of the
    ///     file. Plaintext written since the last 64 KiB boundary therefore stays buffered
    ///     until the stream is disposed, however often you flush. Code driving a framed or
    ///     interactive protocol should not expect <c>Flush</c> to make bytes readable
    ///     downstream.
    /// </remarks>
    /// <param name="destination">The ciphertext destination. Left open when the returned stream is disposed.</param>
    /// <param name="recipients">One or more recipients, e.g. <c>[recipient]</c>.</param>
    /// <param name="options">Encryption options; <see cref="AgeEncryptOptions.Armor" /> selects armored output. Defaults when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="recipients" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="recipients" /> is empty, or contains a null element.</exception>
    public static Stream EncryptWriter(Stream destination, IReadOnlyList<IRecipient> recipients, AgeEncryptOptions? options = null)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(Materialize(recipients, nameof(recipients), "recipient"));

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        CryptographicOperations.ZeroMemory(fileKey);

        // When armoring, ciphertext flows through a push-side armor writer that
        // wraps the caller's destination. The encrypt writer owns (and disposes,
        // to emit the footer) that wrapper but never the caller's destination.
        var armor = options?.Armor == true;
        var inner = armor ? new ArmorWriterStream(destination) : destination;
        return new EncryptWriterStream(headerBytes, payloadNonce, payloadKey, inner, armor);
    }

    /// <summary>
    ///     Returns a readable plaintext <see cref="Stream" /> over an age-encrypted
    ///     <paramref name="source" />. Header parsing and MAC verification happen
    ///     eagerly; payload decryption is lazy. Armored input is auto-detected on any
    ///     stream, seekable or not. Dispose the returned stream when done.
    /// </summary>
    /// <remarks>
    ///     <see cref="Stream.CanSeek" /> mirrors the source: a seekable source yields a
    ///     seekable stream whose <see cref="Stream.Length" /> is the plaintext length
    ///     and whose <see cref="Stream.Seek" /> maps to the containing 64 KiB chunk,
    ///     with the last-read chunk cached; a non-seekable source yields a forward-only
    ///     stream. An ASCII-armored source seeks as well: armor has fixed geometry (48
    ///     bytes per 64-column line, only the last line short), so an offset translates
    ///     arithmetically and the layout is resolved from two small probes rather than
    ///     a scan.
    ///     Opening a seekable source decrypts the final chunk to authenticate the
    ///     plaintext length, so <see cref="Stream.Length" /> is trustworthy and a
    ///     truncated payload is rejected here rather than on reaching the missing tail.
    /// </remarks>
    /// <param name="source">The age-encrypted source (binary or ASCII-armored).</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas, e.g. <c>[identity]</c>.</param>
    /// <param name="options">Parsing options (armor strictness and the header-size limits); defaults are used when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    /// <exception cref="NoIdentityMatchException">None of the identities matched any stanza.</exception>
    /// <exception cref="AgeFormatException">The header (or armor) is malformed.</exception>
    /// <exception cref="AgeAuthenticationException">
    ///     The header MAC failed, or a seekable source's payload is truncated or
    ///     structurally impossible.
    /// </exception>
    public static Stream DecryptReader(Stream source, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null)
    {
        var identityArray = Materialize(identities, nameof(identities), "identity");
        options ??= AgeDecryptOptions.Default;

        var (binaryInput, needsDispose) = DeArmorIfNeeded(source, options);
        byte[]? payloadKey = null;

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identityArray, options);

            try
            {
                var payloadNonce = ReadPayloadNonce(reader);
                payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
            }
            finally
            {
                // In a finally, not inline: a truncated file throws from the nonce read,
                // and the file key must not outlive that. Mirrors DecryptReaderAsync.
                CryptographicOperations.ZeroMemory(fileKey);
            }

            // CanSeek mirrors the (possibly dearmored) source: a seekable input
            // gets random-access decryption; anything else stays forward-only.
            return binaryInput.CanSeek
                ? SeekableDecryptStream.Create(payloadKey, binaryInput, binaryInput.Position, needsDispose)
                : new DecryptStream(payloadKey, binaryInput, needsDispose);
        }
        catch
        {
            if (payloadKey is not null) CryptographicOperations.ZeroMemory(payloadKey);
            if (needsDispose) binaryInput.Dispose();
            throw;
        }
    }

    /// <summary>
    ///     Returns a writable <see cref="Stream" /> that decrypts the age ciphertext
    ///     written to it and forwards plaintext to <paramref name="destination" /> — the
    ///     push counterpart of <see cref="DecryptReader" />,
    ///     for when something else drives the transfer and hands you bytes.
    ///     Disposing the returned stream finalizes decryption;
    ///     <paramref name="destination" /> is never disposed.
    /// </summary>
    /// <remarks>
    ///     Setup is necessarily lazy: nothing about the file is known until enough bytes
    ///     have been written. A header that no identity matches therefore throws from the
    ///     <c>Write</c> that completes the header, not from this call — the one place the
    ///     streaming grid is not symmetric, because the other three learn their key up
    ///     front. Armored input is auto-detected here as everywhere else.
    ///     <para>
    ///         Dispose is not optional: the final STREAM chunk is only recognisable as final
    ///         once the input ends, so a stream that is never disposed has neither
    ///         authenticated the last chunk nor detected a truncated file.
    ///     </para>
    /// </remarks>
    /// <param name="destination">The plaintext destination. Left open when the returned stream is disposed.</param>
    /// <param name="identities">One or more identities tried against the file's recipient stanzas, e.g. <c>[identity]</c>.</param>
    /// <param name="options">Parsing options (armor strictness and the header-size limits); defaults are used when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identities" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="identities" /> is empty, or contains a null element.</exception>
    public static Stream DecryptWriter(Stream destination, IReadOnlyList<IIdentity> identities, AgeDecryptOptions? options = null) =>
        new DecryptWriterStream(destination, Materialize(identities, nameof(identities), "identity"), options ?? AgeDecryptOptions.Default);

    /// <summary>
    ///     Parses the header of an age file without decrypting it (and without
    ///     verifying the header MAC, which requires an identity). Armored input is
    ///     auto-detected on any stream, seekable or not.
    /// </summary>
    /// <remarks>
    ///     The result is <b>unverified</b>. Because no MAC check has happened, stanza
    ///     types, argument counts, and argument contents are all attacker-controlled.
    ///     Treat them as untrusted input — in particular, a stanza may have zero
    ///     arguments, so indexing <see cref="Stanza.Args" /> without checking will throw
    ///     on a hostile file.
    /// </remarks>
    /// <param name="source">The age-encrypted source.</param>
    /// <param name="options">Parsing options (the header-size limits); defaults are used when null.</param>
    public static AgeHeader ReadHeader(Stream source, AgeDecryptOptions? options = null) =>
        AgeHeader.Parse(source, options ?? AgeDecryptOptions.Default);

    // Validates a caller-supplied collection and hands back an array the span-based
    // internals can consume. An array passes through without copying, which is the
    // common case: a collection expression at a call site compiles to one. Every public
    // entry point funnels through here, so this is the single place recipients and
    // identities are checked — for null, for emptiness, and for null elements.
    private static T[] Materialize<T>(IReadOnlyList<T> items, string paramName, string noun)
    {
        ArgumentNullException.ThrowIfNull(items, paramName);

        if (items.Count == 0)
            throw new ArgumentException($"at least one {noun} is required", paramName);

        var array = items as T[] ?? [.. items];

        // Every params overload funnels through here via Combine, so this one scan
        // covers both shapes. Without it a null element surfaces as a NullReference
        // from inside the wrap loop, naming nothing the caller can act on.
        for (var i = 0; i < array.Length; i++)
            if (array[i] is null)
                throw new ArgumentException($"{noun} at index {i} is null", paramName);

        return array;
    }

    // Wrap a recipient and get its label set. Recipients that don't implement
    // IRecipientWithLabels are treated as having an empty set (mirrors the
    // reference implementation's wrapWithLabels helper).
    private static (Stanza stanza, IReadOnlyCollection<string> labels) WrapWithLabels(IRecipient recipient, ReadOnlySpan<byte> fileKey)
    {
        if (recipient is IRecipientWithLabels labelled)
            return labelled.WrapWithLabels(fileKey);

        return (recipient.Wrap(fileKey), []);
    }

    private static bool LabelSetsEqual(IReadOnlyCollection<string> a, IReadOnlyCollection<string> b)
    {
        if (a.Count == 0 && b.Count == 0)
            return true;

        // Set semantics: order-insensitive, duplicates collapse
        var set = new HashSet<string>(a, StringComparer.Ordinal);
        return set.SetEquals(b);
    }

    private static (Header header, byte[] fileKey) BuildHeaderAndFileKey(ReadOnlySpan<IRecipient> recipients)
    {
        var fileKey = new byte[FileKeySize];
        RandomNumberGenerator.Fill(fileKey);

        try
        {
            var header = new Header();

            // Wrap each recipient and collect its label set from the same call —
            // labels can be dynamic (a fresh random label, or plugin-provided),
            // so they must come from the wrap that produced the stanza, not a
            // separately-read property. All label sets must match, compared as
            // unordered sets (age-plugin.md: "treat them as an unordered set").
            IReadOnlyCollection<string>? firstLabels = null;

            for (var i = 0; i < recipients.Length; i++)
            {
                var (stanza, labels) = WrapWithLabels(recipients[i], fileKey);

                if (i == 0)
                    firstLabels = labels;
                else if (!LabelSetsEqual(firstLabels!, labels))
                    throw new AgeException("cannot mix recipients with different security labels");

                header.Stanzas.Add(stanza);
            }

            // A scrypt stanza must be the only stanza in the header — the same rule
            // decryption enforces. Checked post-wrap so custom recipients that emit
            // scrypt stanzas are caught too.
            if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
                throw new AgeException("a passphrase (scrypt) recipient must be the only recipient");

            return (header, fileKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fileKey);
            throw;
        }
    }

    private static byte[] UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities,
        AgeDecryptOptions options)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities, options);
        return fileKey;
    }

    private static (byte[] fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities, AgeDecryptOptions options)
    {
        var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
        var fileKey = UnwrapHeader(reader, identities);
        return (fileKey, reader);
    }

    // Parses the already-read (sync or async-prefilled) header from the reader,
    // enforces the scrypt-alone rule, unwraps the file key with the identities,
    // and verifies the header MAC. No I/O — the reader serves buffered lines, so
    // this is shared verbatim by the sync and async decrypt paths.
    internal static byte[] UnwrapHeader(HeaderReader reader, ReadOnlySpan<IIdentity> identities)
    {
        var header = ParseHeader(reader);

        // Check scrypt constraint: if any stanza is scrypt, it must be the only one
        var hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeFormatException("scrypt stanza must be the only stanza in the header");

        // Try each identity against all stanzas (batch unwrap supports plugin protocol)
        byte[]? fileKey = null;
        foreach (var identity in identities)
        {
            fileKey = identity.Unwrap(header.Stanzas);
            if (fileKey is not null)
                break;
        }

        if (fileKey is null)
            throw new NoIdentityMatchException();

        // Both remaining checks can reject a key that was already recovered, so neither
        // may leave it sitting in memory on the way out.
        try
        {
            if (fileKey.Length != FileKeySize)
                throw new AgeFormatException($"file key must be {FileKeySize} bytes, got {fileKey.Length}");

            header.VerifyMac(fileKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fileKey);
            throw;
        }

        return fileKey;
    }

    // Detects armor by lookahead and, when present, layers a streaming dearmor over
    // the source. Armored input costs one chunk of memory rather than the file's
    // size, and stays seekable when the source is and the armor's geometry resolves;
    // binary input passes straight through with its seekability intact. needsDispose
    // refers to the wrapper only — the caller's stream is never disposed.
    private static (Stream binaryInput, bool needsDispose) DeArmorIfNeeded(Stream input, AgeDecryptOptions options)
    {
        var (source, isArmored) = AsciiArmor.Detect(input, options.RequireArmor);

        return isArmored
            ? (AsciiArmor.Dearmor(source, options.MaxArmorLineBytes), true)
            : (source, false);
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var bytesRead = reader.ReadPayloadBytes(payloadNonce);

        return bytesRead == PayloadNonceSize
            ? payloadNonce
            : throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {bytesRead} bytes");
    }

    private static Header ParseHeader(HeaderReader reader)
    {
        try
        {
            return Header.Parse(reader);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"header parse error: {ex.Message}", ex);
        }
    }
}
