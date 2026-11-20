using AgeSharp;

namespace OuterLoop;

/// <summary>
/// The outer loop's only contact with AgeSharp's public API. The conformance vectors and the
/// go-age and rage interop suites speak age's own terms through it: keys as their text forms,
/// files as bytes, and how a decryption ended as an <see cref="Outcome"/>. When the API is
/// reshaped, this file changes and those suites do not.
/// </summary>
/// <remarks>
/// Text forms are fixed by the age spec (<c>AGE-SECRET-KEY-1…</c>, <c>age1…</c>, an
/// <c>authorized_keys</c> line, a PEM private key), so they outlive any C# name.
/// </remarks>
internal static class AgeUnderTest
{
    /// <summary>A freshly generated key, as its identity and recipient strings.</summary>
    public sealed record KeyPair(string Identity, string Recipient);

    /// <summary>How a decryption ended, in the categories the conformance vectors use.</summary>
    public enum Outcome
    {
        Success,
        NoMatch,
        MacFailure,
        HeaderFailure,
        PayloadFailure,
        ArmorFailure,
    }

    /// <summary>A decryption's outcome, its plaintext on success, and the error's message otherwise.</summary>
    public sealed record Decryption(Outcome Outcome, byte[]? Plaintext, string? Error);

    /// <summary>AgeSharp refused to encrypt, for example to a mix of classical and post-quantum recipients.</summary>
    public sealed class Refused(string message, Exception inner) : Exception(message, inner);

    public static KeyPair GenerateX25519()
    {
        using var identity = X25519Identity.Generate();
        return new KeyPair(identity.ToSecretString(), identity.Recipient.ToString());
    }

    public static KeyPair GeneratePostQuantum()
    {
        using var identity = MlKem768X25519Identity.Generate();
        return new KeyPair(identity.ToSecretString(), identity.Recipient.ToString());
    }

    /// <summary>
    /// Encrypts to recipient strings of any type. With <paramref name="asynchronously"/>, every
    /// read and write goes through the async path.
    /// </summary>
    /// <exception cref="Refused">AgeSharp refused the recipients.</exception>
    public static byte[] Encrypt(byte[] plaintext, bool armored, params string[] recipients) =>
        Encrypt(plaintext, armored, asynchronously: false, recipients);

    /// <inheritdoc cref="Encrypt(byte[], bool, string[])"/>
    public static byte[] Encrypt(byte[] plaintext, bool armored, bool asynchronously, params string[] recipients)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        var options = new AgeEncryptOptions { Armor = armored };

        try
        {
            var to = ParseRecipients(recipients);

            if (asynchronously)
                to.EncryptAsync(input, output, options).GetAwaiter().GetResult();
            else
                to.Encrypt(input, output, options);
        }
        catch (AgeException ex)
        {
            throw new Refused(ex.Message, ex);
        }

        return output.ToArray();
    }

    /// <summary>Encrypts with the header and the payload written apart.</summary>
    public static (byte[] Header, byte[] Payload) EncryptDetached(byte[] plaintext, params string[] recipients)
    {
        using var input = new MemoryStream(plaintext);
        using var header = new MemoryStream();
        using var payload = new MemoryStream();

        ParseRecipients(recipients).EncryptDetached(input, header, payload);
        return (header.ToArray(), payload.ToArray());
    }

    /// <summary>Decrypts with identity strings; anything but success fails the calling test.</summary>
    public static byte[] Decrypt(byte[] ciphertext, params string[] identities)
    {
        var decryption = TryDecrypt(ciphertext, identities);

        return decryption.Outcome == Outcome.Success
            ? decryption.Plaintext!
            : throw new InvalidOperationException($"decryption ended in {decryption.Outcome}: {decryption.Error}");
    }

    /// <summary>
    /// Decrypts with identity strings (X25519, post-quantum, plugin, or a PEM SSH key) and, if
    /// given, a passphrase, and reports how it ended. With <paramref name="overAPipe"/>, the
    /// file is read from a stream that cannot seek.
    /// </summary>
    public static Decryption TryDecrypt(byte[] ciphertext, IReadOnlyList<string> identities, string? passphrase = null, bool overAPipe = false)
    {
        var parsed = ParseIdentities(identities, passphrase);

        // Decrypt needs at least one identity, as in go-age. A file that must fail before any
        // identity is tried gets one that can never match.
        if (parsed.Count == 0)
            parsed.Add(X25519Identity.Generate());

        using Stream input = overAPipe ? new Pipe(ciphertext) : new MemoryStream(ciphertext);
        using var output = new MemoryStream();

        try
        {
            AgeEncrypt.Decrypt(input, output, parsed.ToArray());
            return new Decryption(Outcome.Success, output.ToArray(), null);
        }
        catch (AgeException ex)
        {
            return new Decryption(OutcomeOf(ex), null, $"{ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            foreach (var identity in parsed)
                (identity as IDisposable)?.Dispose();
        }
    }

    // The one place that knows AgeSharp's exception types.
    private static Outcome OutcomeOf(AgeException ex) => ex switch
    {
        NoIdentityMatchException => Outcome.NoMatch,
        AgeHmacException => Outcome.MacFailure,
        AgeHeaderException => Outcome.HeaderFailure,
        AgePayloadException => Outcome.PayloadFailure,
        AgeArmorException => Outcome.ArmorFailure,
        _ => throw new InvalidOperationException($"no outcome for {ex.GetType().Name}: {ex.Message}", ex),
    };

    // A stream that cannot seek, like a pipe or a network socket.
    private sealed class Pipe(byte[] data) : Stream
    {
        private readonly MemoryStream _inner = new(data);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    // Each string is one recipient of any type: an age1… string or an authorized_keys line.
    private static Recipients ParseRecipients(string[] recipients) =>
        new(recipients.Select(r => Recipients.ParseOne(r)));

    private static List<IIdentity> ParseIdentities(IReadOnlyList<string> identities, string? passphrase)
    {
        var parsed = new List<IIdentity>();

        foreach (var identity in identities)
        {
            if (identity.StartsWith("-----BEGIN", StringComparison.Ordinal))
                parsed.Add(AgeKeygen.ParseSshIdentity(identity));
            else
                parsed.AddRange(AgeKeygen.ParseIdentityFile(identity));
        }

        if (passphrase is not null)
            parsed.Add(new ScryptRecipient(passphrase));

        return parsed;
    }
}
