using System.Text;
using Age.Format;
using Age.Plugin;
using Age.Recipients;

namespace Age.Cli;

internal static class AgeCommand
{
    public static int Execute(bool encrypt, bool armor, bool passphrase, string[] recipients, string[] recipientFiles, string[] identityFiles, string? outputPath, string? inputPath)
    {
        var parsedRecipients = recipients.Select(ParseRecipient).ToList();

        return encrypt
            ? Encrypt(armor, passphrase, parsedRecipients, recipientFiles, identityFiles, outputPath, inputPath)
            : Decrypt(passphrase, identityFiles, outputPath, inputPath);
    }

    private static int Encrypt(bool armor, bool passphrase, List<IRecipient> recipients, string[] recipientFiles, string[] identityFiles, string? outputPath, string? inputPath)
    {
        var callbacks = new CliPluginCallbacks();

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

        // Buffer input into a seekable MemoryStream so armor auto-detection works
        using var rawInput = OpenInput(inputPath);
        using var input = new MemoryStream();

        rawInput.CopyTo(input);
        input.Position = 0;

        using var output = OpenOutput(outputPath);
        AgeEncrypt.Decrypt(input, output, [.. identities]);
        return 0;
    }

    private static List<IIdentity> CollectDecryptIdentities(bool passphrase, string[] identityFiles)
    {
        var callbacks = new CliPluginCallbacks();
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

            identities.AddRange(from file in identityFiles from id in LoadIdentities(file, callbacks) select id is ScryptRecipient ? new RejectScryptIdentity() : id);
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

    private static IRecipient ParseRecipient(string s)
    {
        var callbacks = new CliPluginCallbacks();

        if (s.StartsWith("age1pq"))
            return MlKem768X25519Recipient.Parse(s);
        if (s.StartsWith("age1") && s.IndexOf('1', 4) > 0)
            return new PluginRecipient(s, callbacks);
        if (s.StartsWith("age1"))
            return X25519Recipient.Parse(s);
        if (s.StartsWith("ssh-"))
            return AgeKeygen.ParseSshRecipient(s);

        throw new FormatException($"unknown recipient type: {s}");
    }

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

    private static string ReadPassphrase(string prompt)
    {
        var envPass = Environment.GetEnvironmentVariable("AGE_PASSPHRASE");
        if (envPass is not null)
            return envPass;

        Console.Error.Write(prompt);
        var sb = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.Error.WriteLine();
                    return sb.ToString();

                case ConsoleKey.Backspace when sb.Length > 0:
                    sb.Remove(sb.Length - 1, 1);
                    break;

                default:
                    if (key.KeyChar != '\0')
                        sb.Append(key.KeyChar);
                    break;
            }
        }
    }

    private static string GeneratePassphrase()
    {
        var rng = new Random();
        var parts = new string[10];

        for (var i = 0; i < 10; i++)
        {
            var chars = new char[6];
            for (var j = 0; j < 6; j++)
                chars[j] = (char)('a' + rng.Next(26));
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

    /// <summary>
    /// Console-based implementation of <see cref="IPluginCallbacks"/> for CLI use.
    /// </summary>
    private sealed class CliPluginCallbacks : IPluginCallbacks
    {
        public void DisplayMessage(string message) =>
            Console.Error.WriteLine(message);

        public string RequestValue(string prompt, bool secret)
        {
            if (secret)
                return ReadPassphrase(prompt + ": ");

            Console.Error.Write(prompt + ": ");
            return Console.ReadLine() ?? "";
        }

        public bool Confirm(string message, string yes, string? no)
        {
            var options = no is not null ? $"[{yes}/{no}]" : $"[{yes}]";
            Console.Error.Write($"{message} {options} ");
            var response = Console.ReadLine()?.Trim() ?? "";
            return string.Equals(response, yes, StringComparison.OrdinalIgnoreCase);
        }
    }
}