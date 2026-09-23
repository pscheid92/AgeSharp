using System.Security.Cryptography;
using System.Text;
using Age.Format;
using Age.Plugin;
using Age.Recipients;

namespace Age.Cli;

internal static class AgeCommand
{
    /// <param name="encrypt">Whether to encrypt, which is the default; false when -d was given.</param>
    /// <param name="encryptFlag">Whether -e was given explicitly.</param>
    public static int Execute(bool encrypt, bool armor, bool passphrase, string[] recipients, string[] recipientFiles, string[] identityFiles, string? outputPath, string? inputPath, bool encryptFlag = false)
    {
        if (!encrypt)
            RefuseEncryptionOnlyFlags(encryptFlag, armor, recipients, recipientFiles);

        var parsedRecipients = recipients.Select(ParseRecipient).ToList();

        return encrypt
            ? Encrypt(armor, passphrase, parsedRecipients, recipientFiles, identityFiles, outputPath, inputPath)
            : Decrypt(passphrase, identityFiles, outputPath, inputPath);
    }

    /// <summary>
    /// Flags that only mean something when encrypting were silently ignored with -d, and -e -d
    /// decrypted. Refused as go-age refuses them, with its wording and hints; -d -p is this CLI's
    /// own and stays allowed.
    /// </summary>
    private static void RefuseEncryptionOnlyFlags(bool encryptFlag, bool armor, string[] recipients, string[] recipientFiles)
    {
        if (encryptFlag)
            throw new AgeException("-e/--encrypt can't be used with -d/--decrypt");

        if (armor)
            throw new AgeException("-a/--armor can't be used with -d/--decrypt; " +
                                   "armored files are detected automatically, try again without -a/--armor");

        if (recipients.Length > 0)
            throw new AgeException("-r/--recipient can't be used with -d/--decrypt; " +
                                   "did you mean to use -i/--identity to specify a private key?");

        if (recipientFiles.Length > 0)
            throw new AgeException("-R/--recipients-file can't be used with -d/--decrypt; " +
                                   "did you mean to use -i/--identity to specify a private key?");
    }

    private static int Encrypt(bool armor, bool passphrase, List<IRecipient> recipients, string[] recipientFiles, string[] identityFiles, string? outputPath, string? inputPath)
    {
        var callbacks = new CliPluginCallbacks(Terminal.OpenDefault);

        if (passphrase)
        {
            if (recipients.Count > 0 || recipientFiles.Length > 0 || identityFiles.Length > 0)
                throw new AgeException("-p/--passphrase can't be combined with other recipient flags");

            recipients.Add(new ScryptRecipient(ReadAndConfirmPassphrase()));
        }
        else
        {
            CollectRecipientsFromFiles(recipientFiles, identityFiles, recipients, callbacks);

            if (recipients.Count == 0)
                throw new AgeException("missing recipients (-r, -R, or -i required for encryption)");
        }

        if (outputPath is null && !armor && !Console.IsOutputRedirected)
            throw new AgeException("refusing to output binary to a terminal. Did you mean to use -a/--armor?");

        using var input = OpenInput(inputPath);
        using var output = OpenOutput(outputPath);

        AgeEncrypt.Encrypt(input, output, armor, [.. recipients]);
        return 0;
    }

    private static void CollectRecipientsFromFiles(string[] recipientFiles, string[] identityFiles, List<IRecipient> recipients, IPluginCallbacks callbacks)
    {
        foreach (var file in recipientFiles)
        {
            var text = File.ReadAllText(file);
            recipients.AddRange(AgeKeygen.ParseRecipientsFile(text, callbacks));
        }

        foreach (var file in identityFiles)
        {
            var identities = LoadIdentities(file, callbacks);
            foreach (var id in identities)
            {
                if (GetRecipientFromIdentity(id) is { } recipient)
                    recipients.Add(recipient);
                else
                    Console.Error.WriteLine("warning: skipping identity without public recipient extraction (plugin identity)");
            }
        }
    }

    private static string ReadAndConfirmPassphrase()
    {
        var pass = ReadPassphrase("Enter passphrase (leave empty to autogenerate): ");

        if (pass.Length == 0)
        {
            pass = GeneratePassphrase();
            Console.Error.WriteLine($"using auto-generated passphrase \"{pass}\"");
            return pass;
        }

        if (Environment.GetEnvironmentVariable("AGE_PASSPHRASE") is not null)
            return pass;

        var confirm = ReadPassphrase("Confirm passphrase: ");
        return pass == confirm ? pass : throw new AgeException("passphrases didn't match");
    }

    private static int Decrypt(bool passphrase, string[] identityFiles, string? outputPath, string? inputPath)
    {
        var identities = CollectDecryptIdentities(passphrase, identityFiles);

        using var rawInput = OpenInput(inputPath);
        using var input = SeekableInput.From(rawInput);

        using var output = OpenOutput(outputPath);
        AgeEncrypt.Decrypt(input, output, [.. identities]);
        return 0;
    }

    private static List<IIdentity> CollectDecryptIdentities(bool passphrase, string[] identityFiles)
    {
        var callbacks = new CliPluginCallbacks(Terminal.OpenDefault);
        var identities = new List<IIdentity>();

        if (passphrase)
        {
            if (identityFiles.Length > 0)
                throw new AgeException("-p/--passphrase can't be combined with -i/--identity");

            identities.Add(new LazyPassphraseIdentity());
        }
        else
        {
            if (identityFiles.Length == 0)
                throw new AgeException("missing identity (-i required for decryption, or use -p for passphrase)");

            // First, so a passphrase-encrypted file is explained before any identity — a plugin
            // process, say — is tried against its scrypt stanza.
            identities.Add(new RejectScryptIdentity());

            foreach (var file in identityFiles)
                identities.AddRange(LoadIdentities(file, callbacks));
        }

        return identities;
    }

    private static IRecipient? GetRecipientFromIdentity(IIdentity identity) => identity switch
    {
        X25519Identity x => x.Recipient,
        MlKem768X25519Identity pq => pq.Recipient,
        SshEd25519Identity ssh => ssh.Recipient,
        SshRsaIdentity ssh => ssh.Recipient,
        _ => null
    };

    private static IRecipient ParseRecipient(string s) =>
        AgeKeygen.ParseRecipientLine(s, new CliPluginCallbacks(Terminal.OpenDefault));

    private static List<IIdentity> LoadIdentities(string path, IPluginCallbacks callbacks)
    {
        var bytes = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(bytes);
        var trimmed = text.TrimStart();

        // Encrypted identity file
        if (trimmed.StartsWith("age-encryption.org/v1") || trimmed.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----"))
        {
            var pass = ReadPassphrase($"Enter passphrase for identity file \"{path}\": ");
            return [.. AgeKeygen.DecryptIdentityFile(bytes, pass)];
        }

        // SSH private key
        if (trimmed.StartsWith("-----BEGIN"))
            return [AgeKeygen.ParseSshIdentity(text)];

        // Standard age identity file (AGE-SECRET-KEY-, AGE-SECRET-KEY-PQ-, AGE-PLUGIN-)
        return [.. AgeKeygen.ParseIdentityFile(text, callbacks)];
    }

    private static string ReadPassphrase(string prompt) =>
        Environment.GetEnvironmentVariable("AGE_PASSPHRASE") ?? Terminal.ReadSecret(prompt);

    private static string GeneratePassphrase()
    {
        // This passphrase is the sole secret protecting the encrypted file, so it
        // must come from a cryptographically secure RNG — never System.Random.
        var parts = new string[10];

        for (var i = 0; i < 10; i++)
        {
            var chars = new char[6];
            for (var j = 0; j < 6; j++)
                chars[j] = (char)('a' + RandomNumberGenerator.GetInt32(26));
            parts[i] = new string(chars);
        }

        return string.Join("-", parts);
    }

    private static Stream OpenInput(string? path) =>
        path is not null ? File.OpenRead(path) : Console.OpenStandardInput();

    private static Stream OpenOutput(string? path) =>
        path is not null ? new LazyFileStream(path) : Console.OpenStandardOutput();

    /// <summary>
    /// A passphrase identity that lazily prompts the user on first use.
    /// Used for <c>age -d -p</c> mode.
    /// </summary>
    private sealed class LazyPassphraseIdentity : IIdentity
    {
        private ScryptRecipient? _inner;

        public byte[]? Unwrap(Stanza stanza)
        {
            _inner ??= new ScryptRecipient(ReadPassphrase("Enter passphrase: "));
            return _inner.Unwrap(stanza);
        }
    }

    /// <summary>
    /// An identity wrapper that rejects scrypt stanzas when using identity files.
    /// Prevents passphrase-encrypted files from being accidentally decrypted with <c>-i</c>.
    /// </summary>
    private sealed class RejectScryptIdentity : IIdentity
    {
        public byte[]? Unwrap(Stanza stanza) =>
            stanza.Type == "scrypt"
                ? throw new AgeException("passphrase-encrypted file can't be decrypted with -i; use -p instead")
                : null;
    }

    /// <summary>
    /// A stream that lazily creates the output file on first write.
    /// Prevents creating empty output files on errors.
    /// </summary>
    private sealed class LazyFileStream : Stream
    {
        private readonly string _path;
        private FileStream? _inner;

        public LazyFileStream(string path) => _path = path;

        private FileStream Inner => _inner ??= File.Create(_path);

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Inner.Length;

        public override long Position
        {
            get => Inner.Position;
            set => Inner.Position = value;
        }

        public override void Flush() => _inner?.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => Inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => Inner.Write(buffer, offset, count);
        public override void Write(ReadOnlySpan<byte> buffer) => Inner.Write(buffer);

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner?.Dispose();
            base.Dispose(disposing);
        }
    }

}