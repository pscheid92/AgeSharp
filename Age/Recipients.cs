using System.Collections;
using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// The recipients a file is encrypted to: every one of them can decrypt it. A set is fixed once
/// built, and encrypting to it wraps one fresh file key for each member.
/// </summary>
/// <example>
/// <code>
/// var to = new Recipients(alice, bob);
/// to.Encrypt(plaintext, ciphertext, new AgeEncryptOptions { Armor = true });
///
/// var team = Recipients.Parse(File.ReadAllText("recipients.txt"));
/// byte[] sealedBytes = team.Encrypt(secret);
/// </code>
/// </example>
/// <remarks>
/// Building a set checks what can be checked without a file key: it is not empty, holds no
/// null, and a passphrase is not mixed with anything else. The security labels a recipient
/// declares (post-quantum, a plugin's own) come with its stanzas, so they are compared when
/// encrypting, and a mix is refused before anything is written.
/// <para>
/// Encrypting does not dispose the streams it is given, nor the recipients.
/// </para>
/// </remarks>
public sealed class Recipients : IReadOnlyList<IRecipient>
{
    private readonly IRecipient[] _members;

    /// <summary>A set of the given recipients, in the order given.</summary>
    /// <exception cref="ArgumentException">No recipient was given, or one is null.</exception>
    /// <exception cref="AgeException">A passphrase recipient was combined with others.</exception>
    public Recipients(params ReadOnlySpan<IRecipient> recipients)
    {
        ArgumentException.ThrowIfEmpty(recipients, "recipient");

        foreach (var recipient in recipients)
        {
            if (recipient is null)
                throw new ArgumentException("a recipient is null", nameof(recipients));

            // A scrypt stanza must be the only stanza in the header, as decryption requires.
            if (recipient is ScryptRecipient && recipients.Length > 1)
                throw new AgeException(PassphraseNotAlone);
        }

        _members = recipients.ToArray();
    }

    /// <inheritdoc cref="Recipients(ReadOnlySpan{IRecipient})"/>
    public Recipients(IEnumerable<IRecipient> recipients)
        : this([.. recipients ?? throw new ArgumentNullException(nameof(recipients))])
    {
    }

    private const string PassphraseNotAlone = "a passphrase (scrypt) recipient must be the only recipient";

    /// <summary>The number of recipients.</summary>
    public int Count => _members.Length;

    /// <summary>The recipient at <paramref name="index"/>, in the order the set was built.</summary>
    public IRecipient this[int index] => _members[index];

    /// <inheritdoc/>
    public IEnumerator<IRecipient> GetEnumerator() => ((IEnumerable<IRecipient>)_members).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>
    /// Parses a recipients file: one recipient per line, of any type <see cref="ParseOne"/>
    /// accepts. Empty lines and lines starting with <c>#</c> are skipped; LF and CRLF line
    /// endings are both accepted.
    /// </summary>
    /// <param name="text">The file's contents.</param>
    /// <param name="plugins">Lets plugin recipients talk to the user; without it they cannot prompt.</param>
    /// <exception cref="FormatException">A line is not a recipient, naming the line, or the file has none.</exception>
    public static Recipients Parse(string text, IPluginCallbacks? plugins = null)
    {
        ArgumentNullException.ThrowIfNull(text);

        var parsed = new List<IRecipient>();
        var lineNumber = 0;

        foreach (var raw in text.Split('\n'))
        {
            lineNumber++;
            var line = raw.TrimEnd('\r');

            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            try
            {
                parsed.Add(ParseOne(line, plugins));
            }
            catch (FormatException ex)
            {
                throw new FormatException($"recipients file, line {lineNumber}: {ex.Message}", ex);
            }
        }

        if (parsed.Count == 0)
            throw new FormatException("recipients file has no recipients");

        // A file holds no passphrase, so nothing here can mix one with others.
        return new Recipients(parsed);
    }

    /// <summary>
    /// Parses one recipient of any type: X25519 (<c>age1…</c>), ML-KEM-768-X25519
    /// (<c>age1pq1…</c>), the two tagged types (<c>age1tag1…</c>, <c>age1tagpq1…</c>), a plugin
    /// (<c>age1name1…</c>), or an SSH public key (an <c>ssh-ed25519</c> or <c>ssh-rsa</c>
    /// <c>authorized_keys</c> line).
    /// </summary>
    /// <param name="s">The recipient's text form.</param>
    /// <param name="plugins">Lets a plugin recipient talk to the user; without it, it cannot prompt.</param>
    /// <exception cref="FormatException">The text is not a recipient of a known type.</exception>
    public static IRecipient ParseOne(string s, IPluginCallbacks? plugins = null)
    {
        ArgumentNullException.ThrowIfNull(s);

        // Dispatch on the true bech32 HRP — everything before the LAST '1' (BIP-173), since
        // data never contains '1'. String prefixes are ambiguous here: 'p' and 'q' are data
        // characters, so an X25519 recipient's data can itself start with "pq" ("age1pq...").
        var sep = s.LastIndexOf('1');
        var hrp = sep > 0 ? s[..sep] : "";

        return hrp switch
        {
            "age" => X25519Recipient.Parse(s),
            "age1pq" => MlKem768X25519Recipient.Parse(s),
            "age1tag" => P256TagRecipient.Parse(s),
            "age1tagpq" => MlKem768P256TagRecipient.Parse(s),
            _ when hrp.StartsWith("age1", StringComparison.Ordinal) => new PluginRecipient(s, plugins),
            _ when s.StartsWith("ssh-", StringComparison.Ordinal) => ParseSsh(s),
            _ => throw new FormatException($"unrecognized recipient: {s}")
        };
    }

    /// <summary>An SSH recipient from an <c>authorized_keys</c> line, Ed25519 or RSA.</summary>
    internal static IRecipient ParseSsh(string authorizedKeysLine)
    {
        // ParsePublicKey refuses every type but these two.
        var (keyType, _, _) = SshKeyParser.ParsePublicKey(authorizedKeysLine);

        return keyType == "ssh-ed25519"
            ? SshEd25519Recipient.Parse(authorizedKeysLine)
            : SshRsaRecipient.Parse(authorizedKeysLine);
    }

    /// <summary>Encrypts <paramref name="plaintext"/>, writing the age file to <paramref name="ciphertext"/>.</summary>
    /// <param name="plaintext">Read once, start to end.</param>
    /// <param name="ciphertext">Where the file is written.</param>
    /// <param name="options">Whether to armor; binary by default.</param>
    /// <exception cref="AgeException">The recipients declare different security labels.</exception>
    public void Encrypt(Stream plaintext, Stream ciphertext, AgeEncryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        using var stream = EncryptReader(plaintext, options);
        stream.CopyTo(ciphertext);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into a new array: the convenience for small values
    /// such as secrets or database fields.
    /// </summary>
    /// <remarks>The copy of the plaintext this makes on the way in is cleared before returning.</remarks>
    /// <exception cref="AgeException">The recipients declare different security labels.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, AgeEncryptOptions? options = null)
    {
        var copy = plaintext.ToArray();

        try
        {
            using var output = new MemoryStream();
            Encrypt(new MemoryStream(copy), output, options);
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> asynchronously, writing the age file to
    /// <paramref name="ciphertext"/>. Every read and write on the two streams is asynchronous.
    /// </summary>
    /// <remarks>
    /// Wrapping the file key happens before the first read. For a plugin recipient that is a
    /// synchronous exchange with the plugin's process.
    /// </remarks>
    /// <exception cref="AgeException">The recipients declare different security labels.</exception>
    public async Task EncryptAsync(Stream plaintext, Stream ciphertext, AgeEncryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        var stream = EncryptReader(plaintext, options);

        await using (stream.ConfigureAwait(false))
            await stream.CopyToAsync(ciphertext, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A stream that produces the age file as it is read. The file key is wrapped and the header
    /// written before this returns; the payload is encrypted a chunk at a time as it is read,
    /// synchronously or asynchronously. Dispose it when done; that leaves
    /// <paramref name="plaintext"/> open.
    /// </summary>
    /// <exception cref="AgeException">The recipients declare different security labels.</exception>
    public Stream EncryptReader(Stream plaintext, AgeEncryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        options ??= AgeEncryptOptions.Default;

        using var fileKey = FileKey.Fresh();

        using var headerBytes = new MemoryStream();
        BuildHeader(fileKey.Bytes).WriteTo(headerBytes, fileKey.Bytes);

        var (nonce, payloadKey) = NewPayloadKey(fileKey);
        var binary = new EncryptStream(headerBytes.ToArray(), nonce, payloadKey, plaintext);
        return options.Armor ? new ArmorStream(binary) : binary;
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/>, writing the header to <paramref name="header"/> and
    /// the payload to <paramref name="payload"/>, for when the two are kept apart (a metadata
    /// store and a blob store, say).
    /// </summary>
    /// <remarks>
    /// Takes no options: armor wraps a whole age file, which a detached header and payload are
    /// not.
    /// </remarks>
    /// <exception cref="AgeException">The recipients declare different security labels.</exception>
    public void EncryptDetached(Stream plaintext, Stream header, Stream payload)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        using var fileKey = FileKey.Fresh();
        BuildHeader(fileKey.Bytes).WriteTo(header, fileKey.Bytes);

        var (nonce, payloadKey) = NewPayloadKey(fileKey);
        using var stream = new EncryptStream([], nonce, payloadKey, plaintext);
        stream.CopyTo(payload);
    }

    /// <summary>The asynchronous form of <see cref="EncryptDetached"/>.</summary>
    /// <exception cref="AgeException">The recipients declare different security labels.</exception>
    public async Task EncryptDetachedAsync(Stream plaintext, Stream header, Stream payload, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        byte[] headerBytes;
        EncryptStream stream;

        // The key is cleared before the first await, so no continuation holds it.
        using (var fileKey = FileKey.Fresh())
        {
            using var buffer = new MemoryStream();
            BuildHeader(fileKey.Bytes).WriteTo(buffer, fileKey.Bytes);
            headerBytes = buffer.ToArray();
            var (nonce, payloadKey) = NewPayloadKey(fileKey);
            stream = new EncryptStream([], nonce, payloadKey, plaintext);
        }

        await using (stream.ConfigureAwait(false))
        {
            await header.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            await stream.CopyToAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    // A fresh nonce, and the payload key derived from it. The EncryptStream that is handed the
    // key clears it when disposed.
    private static (byte[] Nonce, byte[] Key) NewPayloadKey(FileKey fileKey)
    {
        var nonce = new byte[StreamEncryption.PayloadNonceSize];
        RandomNumberGenerator.Fill(nonce);
        return (nonce, CryptoHelper.HkdfDerive(fileKey.Bytes, nonce, "payload", StreamEncryption.PayloadKeySize));
    }

    /// <summary>
    /// Wraps <paramref name="fileKey"/> for every member and returns the resulting header.
    /// </summary>
    /// <remarks>
    /// Takes the file key rather than creating one, so that whoever created it also holds the
    /// only <c>using</c> that clears it. When this returned the key as well, a caller reading
    /// its own method could not tell whether a throw in here leaked — the guarantee lived in
    /// another method's <c>catch</c>. That non-locality is how S9 happened. Nothing here owns
    /// the key, so nothing here has to remember to clear it.
    /// </remarks>
    private Header BuildHeader(ReadOnlySpan<byte> fileKey)
    {
        var header = new Header();
        HashSet<string>? firstLabels = null;

        foreach (var recipient in _members)
        {
            var (stanzas, labels) = recipient is IRecipientWithLabels labelled
                ? labelled.WrapWithLabels(fileKey)
                : new LabelledStanzas(recipient.Wrap(fileKey), []);

            // A header without this recipient's stanza would leave out a recipient the caller
            // named, which is not something to do silently. Null (a default LabelledStanzas, or
            // a custom Wrap returning null) is the same mistake.
            if (stanzas is null || stanzas.Count == 0)
                throw new AgeException($"recipient {recipient.GetType().Name} produced no stanzas");

            // age-plugin.md:227: every stanza wrapping one file key must carry exactly the same
            // label set. Agreeing with the first recipient's set implies agreeing pairwise. The
            // comparison is ordinal whatever set type the recipient handed over.
            var labelSet = new HashSet<string>(labels ?? [], StringComparer.Ordinal);

            if (firstLabels is null)
                firstLabels = labelSet;
            else if (!firstLabels.SetEquals(labelSet))
                throw new AgeException(IncompatibleLabels(firstLabels, labelSet));

            header.Stanzas.AddRange(stanzas);
        }

        // Checked again after wrapping, for a custom recipient that writes a scrypt stanza, or
        // a plugin that answers with one alongside others.
        if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
            throw new AgeException(PassphraseNotAlone);

        return header;
    }

    /// <summary>
    /// Explains a label mismatch, naming the consequence when post-quantum security is what was
    /// lost. "Different security labels" is accurate but leaves the user to work out the cost.
    /// </summary>
    private static string IncompatibleLabels(HashSet<string> a, HashSet<string> b)
    {
        const string postQuantum = "postquantum";

        if (a.Contains(postQuantum) != b.Contains(postQuantum))
            return "cannot mix post-quantum and classical recipients: the file would be "
                 + "readable by a quantum computer, so the post-quantum recipient buys nothing";

        return $"cannot mix recipients with different security labels: {Describe(a)} and {Describe(b)}";

        static string Describe(HashSet<string> labels) =>
            labels.Count == 0 ? "none" : string.Join(", ", labels.Order(StringComparer.Ordinal).Select(l => $"\"{l}\""));
    }
}
