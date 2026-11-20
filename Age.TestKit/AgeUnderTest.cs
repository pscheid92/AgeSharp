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
    public sealed record Result(Outcome Outcome, byte[]? Plaintext, string? Error);

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

    /// <summary>How a file is written: from a stream, synchronously or not, or through a writer.</summary>
    public enum Encryption
    {
        Stream,
        StreamAsync,
        Writer,
        WriterAsync,
    }

    /// <summary>
    /// How a file is read: whole from a seekable stream, from a pipe, pushed into a writer, or
    /// through the seekable reader a seekable binary file gets.
    /// </summary>
    public enum Decryption
    {
        File,
        Pipe,
        PipeAsync,
        Writer,
        WriterAsync,
        Seekable,
        SeekableAsync,
    }

    /// <summary>Encrypts to recipient strings of any type.</summary>
    /// <exception cref="Refused">AgeSharp refused the recipients.</exception>
    public static byte[] Encrypt(byte[] plaintext, bool armored, params string[] recipients) =>
        Encrypt(plaintext, armored, Encryption.Stream, recipients);

    /// <inheritdoc cref="Encrypt(byte[], bool, string[])"/>
    public static byte[] Encrypt(byte[] plaintext, bool armored, Encryption way, params string[] recipients)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        var options = new AgeEncryptOptions { Armor = armored };

        try
        {
            var to = ParseRecipients(recipients);

            switch (way)
            {
                case Encryption.Stream:
                    to.Encrypt(input, output, options);
                    break;

                case Encryption.StreamAsync:
                    to.EncryptAsync(input, output, options).GetAwaiter().GetResult();
                    break;

                case Encryption.Writer:
                    using (var writer = to.EncryptWriter(output, options))
                        WriteInPieces(writer, plaintext, 4093);
                    break;

                default:
                    WriteInPiecesAsync(to.EncryptWriter(output, options), plaintext, 61).GetAwaiter().GetResult();
                    break;
            }
        }
        catch (AgeException ex)
        {
            throw new Refused(ex.Message, ex);
        }

        return output.ToArray();
    }

    // Writes in pieces of a size that divides nothing in the format, so they split lines, the
    // header, the nonce and chunks anywhere; then disposes, which is what ends a writer's input.
    private static void WriteInPieces(Stream writer, byte[] data, int piece)
    {
        for (var at = 0; at < data.Length; at += piece)
            writer.Write(data, at, Math.Min(piece, data.Length - at));
    }

    // Through the async reader, read into a buffer rather than copied, so ReadAsync itself is used.
    private static async Task ReadAsync(Identities with, Stream input, Stream output)
    {
        await using var reader = await with.DecryptReaderAsync(input);
        var buffer = new byte[10_007];
        int read;

        while ((read = await reader.ReadAsync(buffer)) > 0)
            output.Write(buffer, 0, read);
    }

    private static async Task WriteInPiecesAsync(Stream writer, byte[] data, int piece)
    {
        await using (writer)
        {
            for (var at = 0; at < data.Length; at += piece)
                await writer.WriteAsync(data.AsMemory(at, Math.Min(piece, data.Length - at)));
        }
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
    public static byte[] Decrypt(byte[] ciphertext, params string[] identities) =>
        Decrypt(ciphertext, Decryption.File, identities);

    /// <summary>Decrypts the given way; anything but success fails the calling test.</summary>
    public static byte[] Decrypt(byte[] ciphertext, Decryption way, params string[] identities)
    {
        var decryption = TryDecrypt(ciphertext, identities, way: way);

        return decryption.Outcome == Outcome.Success
            ? decryption.Plaintext!
            : throw new InvalidOperationException($"decryption ended in {decryption.Outcome}: {decryption.Error}");
    }

    /// <summary>
    /// Decrypts with identity strings (X25519, post-quantum, plugin, or a PEM SSH key) and, if
    /// given, a passphrase, and reports how it ended, read the given way.
    /// </summary>
    public static Result TryDecrypt(byte[] ciphertext, IReadOnlyList<string> identities, string? passphrase = null,
                                    Decryption way = Decryption.File)
    {
        var parsed = ParseIdentities(identities, passphrase);

        // Decrypt needs at least one identity, as in go-age. A file that must fail before any
        // identity is tried gets one that can never match.
        if (parsed.Count == 0)
            parsed.Add(X25519Identity.Generate());

        using Stream input = way is Decryption.File or Decryption.Seekable or Decryption.SeekableAsync
            ? new MemoryStream(ciphertext)
            : new Pipe(ciphertext);
        using var output = new MemoryStream();
        var with = new Identities(parsed);

        try
        {
            switch (way)
            {
                case Decryption.File or Decryption.Pipe:
                    with.Decrypt(input, output);
                    break;

                case Decryption.PipeAsync:
                    with.DecryptAsync(input, output).GetAwaiter().GetResult();
                    break;

                case Decryption.Writer:
                    using (var writer = with.DecryptWriter(output))
                        WriteInPieces(writer, ciphertext, 4093);
                    break;

                case Decryption.WriterAsync:
                    WriteInPiecesAsync(with.DecryptWriter(output), ciphertext, 61).GetAwaiter().GetResult();
                    break;

                case Decryption.Seekable:
                    using (var reader = with.DecryptReader(input))
                        reader.CopyTo(output);
                    break;

                default:
                    ReadAsync(with, input, output).GetAwaiter().GetResult();
                    break;
            }

            return new Result(Outcome.Success, output.ToArray(), null);
        }
        catch (AgeException ex)
        {
            return new Result(OutcomeOf(ex), null, $"{ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            foreach (var identity in parsed)
                identity.Dispose();
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
                parsed.Add(SshIdentity.Parse(identity));
            else
                parsed.AddRange(Identities.Parse(identity));
        }

        if (passphrase is not null)
            parsed.Add(new Passphrase(passphrase));

        return parsed;
    }
}
