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
    /// <param name="streams">The standard streams; the console's when null.</param>
    public static int Execute(bool encrypt, bool armor, bool passphrase, string[] recipients, string[] recipientFiles, string[] identityFiles, string? outputPath, string? inputPath, bool encryptFlag = false, StandardStreams? streams = null)
    {
        streams ??= StandardStreams.FromConsole();

        if (!encrypt)
            RefuseEncryptionOnlyFlags(encryptFlag, armor, recipients, recipientFiles);

        RefuseOutputThatIsAnInput(outputPath, [inputPath, .. identityFiles, .. recipientFiles]);

        var parsedRecipients = recipients.Select(ParseRecipient).ToList();

        return encrypt
            ? Encrypt(armor, passphrase, parsedRecipients, recipientFiles, identityFiles, outputPath, inputPath, streams)
            : Decrypt(passphrase, identityFiles, outputPath, inputPath, streams);
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

    /// <summary>
    /// The output must not be a file the command reads — the input, an identity file or a
    /// recipients file. go-age v1.3.2 refuses it; here, -d -i key.txt -o key.txt overwrote the
    /// private key with the plaintext.
    /// </summary>
    /// <remarks>
    /// Paths are compared first. go-age also compares the files themselves, catching symlinks,
    /// hard links and case variants; .NET has no public way to ask whether two paths are one file,
    /// so this asks the OS's file locks instead. With an input held open for shared reading, an
    /// exclusive open of the output fails only if it is the same file. The probe opens the output
    /// read-only, so it cannot truncate anything. Where .NET's file locking is disabled only the
    /// paths are compared, and an output another process holds exclusively reads as the same.
    /// </remarks>
    private static void RefuseOutputThatIsAnInput(string? outputPath, string?[] inputPaths)
    {
        if (outputPath is null or "-")
            return;

        var inputs = inputPaths.OfType<string>().Where(path => path != "-").ToList();
        var output = Path.GetFullPath(outputPath);

        if (inputs.Any(input => Path.GetFullPath(input) == output) ||
            (File.Exists(output) && inputs.Any(input => IsSameFile(input, output))))
            throw new AgeException($"input and output file are the same: \"{outputPath}\"");

        static bool IsSameFile(string input, string output)
        {
            FileStream held;

            try
            {
                held = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Unreadable or missing: the command itself will report that.
                return false;
            }

            using (held)
            {
                try
                {
                    using var probe = new FileStream(output, FileMode.Open, FileAccess.Read, FileShare.None);
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return true;
                }
            }
        }
    }

    private static int Encrypt(bool armor, bool passphrase, List<IRecipient> recipients, string[] recipientFiles, string[] identityFiles, string? outputPath, string? inputPath, StandardStreams streams)
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

        if (outputPath is null && !armor && streams.OutputIsTerminal)
            throw new AgeException("refusing to output binary to a terminal. Did you mean to use -a/--armor? " +
                                   "Force it anyway with \"-o -\".");

        using var input = OpenInput(inputPath, streams);
        using var output = OpenOutput(outputPath, streams);

        AgeEncrypt.Encrypt(input, output, armor, [.. recipients]);
        return 0;
    }

    private static void CollectRecipientsFromFiles(string[] recipientFiles, string[] identityFiles, List<IRecipient> recipients, IPluginCallbacks callbacks)
    {
        foreach (var file in recipientFiles)
        {
            var bytes = ReadKeyFile(file);
            if (bytes.Length > KeyFileLimit)
                throw new AgeException($"\"{file}\": recipients file is too long");

            recipients.AddRange(AgeKeygen.ParseRecipientsFile(Encoding.UTF8.GetString(bytes), callbacks));
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

    private static int Decrypt(bool passphrase, string[] identityFiles, string? outputPath, string? inputPath, StandardStreams streams)
    {
        var identities = CollectDecryptIdentities(passphrase, identityFiles);

        using var rawInput = OpenInput(inputPath, streams);
        using var input = SeekableInput.From(rawInput);

        // Bound for a terminal, the plaintext is held back and shown only if it is text, as go-age
        // does: whatever the file's author chose could otherwise drive the terminal. "-o -" names
        // standard output explicitly and skips the check.
        if (outputPath is null && streams.OutputIsTerminal)
            return DecryptToTerminal(input, identities, streams);

        using var output = OpenOutput(outputPath, streams);
        AgeEncrypt.Decrypt(input, output, [.. identities]);
        return 0;
    }

    private static int DecryptToTerminal(Stream input, List<IIdentity> identities, StandardStreams streams)
    {
        using var plaintext = new MemoryStream();

        try
        {
            AgeEncrypt.Decrypt(input, plaintext, [.. identities]);
            var shown = plaintext.GetBuffer().AsSpan(0, (int)plaintext.Length);

            if (!Terminal.IsPrintable(shown))
                throw new AgeException("refusing to output binary to the terminal; force it anyway with \"-o -\"");

            using var terminal = streams.OpenOutput();
            terminal.Write(shown);
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext.GetBuffer());
        }
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

    // Key files are read into memory whole, so their size is bounded, with go-age v1.3.2's limits
    // (cmd/age/parse.go): 16 MiB for recipients and identity files, under 16 KiB for an SSH key.
    private const int KeyFileLimit = 16 * 1024 * 1024;
    private const int SshKeyFileLimit = 16 * 1024;

    /// <summary>At most one byte past <see cref="KeyFileLimit"/>, so an oversized file is detectable.</summary>
    private static byte[] ReadKeyFile(string path)
    {
        using var file = File.OpenRead(path);
        var contents = new byte[Math.Min(file.Length, KeyFileLimit + 1)];
        var read = file.ReadAtLeast(contents, contents.Length, throwOnEndOfStream: false);
        return read == contents.Length ? contents : contents[..read];
    }

    private static List<IIdentity> LoadIdentities(string path, IPluginCallbacks callbacks)
    {
        var bytes = ReadKeyFile(path);
        var text = Encoding.UTF8.GetString(bytes);
        var trimmed = text.TrimStart();

        // Encrypted identity file. go-age limits its decrypted contents to under 16 MiB; limiting
        // the file itself is stricter only for an armored file holding over ~11.6 MiB of keys.
        if (trimmed.StartsWith("age-encryption.org/v1") || trimmed.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----"))
        {
            if (bytes.Length >= KeyFileLimit)
                throw new AgeException($"failed to read \"{path}\": file too long");

            var pass = ReadPassphrase($"Enter passphrase for identity file \"{path}\": ");
            return [.. AgeKeygen.DecryptIdentityFile(bytes, pass)];
        }

        // SSH private key
        if (trimmed.StartsWith("-----BEGIN"))
        {
            if (bytes.Length >= SshKeyFileLimit)
                throw new AgeException($"failed to read \"{path}\": file too long");

            return [AgeKeygen.ParseSshIdentity(text)];
        }

        // Standard age identity file (AGE-SECRET-KEY-, AGE-SECRET-KEY-PQ-, AGE-PLUGIN-)
        if (bytes.Length > KeyFileLimit)
            throw new AgeException("identities file is too long");

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

    // "-" names standard input or output, as in go-age.
    private static Stream OpenInput(string? path, StandardStreams streams) =>
        path is null or "-" ? streams.OpenInput() : File.OpenRead(path);

    private static Stream OpenOutput(string? path, StandardStreams streams) =>
        path is null or "-" ? streams.OpenOutput() : new LazyFileStream(path);

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