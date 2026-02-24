using System.Text;
using Age.Plugin;
using Age.Recipients;

namespace Age.Cli;

internal static class AgeCommand
{
    public static int Run(string[] args)
    {
        var encrypt = true;
        var armor = false;
        var passphrase = false;
        var recipients = new List<IRecipient>();
        var identityFiles = new List<string>();
        var recipientFiles = new List<string>();
        string? outputPath = null;
        string? inputPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return 0;
                case "--version":
                    Console.WriteLine("age-sharp v0.1.0");
                    return 0;
                case "-d" or "--decrypt":
                    encrypt = false;
                    break;
                case "-e" or "--encrypt":
                    encrypt = true;
                    break;
                case "-a" or "--armor":
                    armor = true;
                    break;
                case "-p" or "--passphrase":
                    passphrase = true;
                    break;
                case "-r" or "--recipient":
                    if (++i >= args.Length)
                    {
                        Error("flag needs an argument: -r");
                        return 1;
                    }
                    recipients.Add(ParseRecipient(args[i]));
                    break;
                case "-R" or "--recipients-file":
                    if (++i >= args.Length)
                    {
                        Error("flag needs an argument: -R");
                        return 1;
                    }
                    recipientFiles.Add(args[i]);
                    break;
                case "-i" or "--identity":
                    if (++i >= args.Length)
                    {
                        Error("flag needs an argument: -i");
                        return 1;
                    }
                    identityFiles.Add(args[i]);
                    break;
                case "-o" or "--output":
                    if (++i >= args.Length)
                    {
                        Error("flag needs an argument: -o");
                        return 1;
                    }
                    outputPath = args[i];
                    break;
                default:
                    if (args[i].StartsWith('-'))
                    {
                        Error($"unknown option: {args[i]}");
                        return 1;
                    }
                    if (inputPath != null)
                    {
                        Error($"unexpected argument: {args[i]}");
                        return 1;
                    }
                    inputPath = args[i];
                    break;
            }
        }

        try
        {
            if (encrypt)
                return Encrypt(recipients, recipientFiles, identityFiles, passphrase, armor, inputPath, outputPath);
            else
                return Decrypt(identityFiles, passphrase, inputPath, outputPath);
        }
        catch (Exception ex) when (ex is AgeException or FormatException)
        {
            Error(ex.Message);
            return 1;
        }
        catch (Exception ex)
        {
            Error($"internal error: {ex.Message}");
            Error($"This is a bug. Please report it at https://github.com/pscheid92/AgeSharp/issues");
            return 1;
        }
    }

    private static int Encrypt(
        List<IRecipient> recipients,
        List<string> recipientFiles,
        List<string> identityFiles,
        bool passphrase,
        bool armor,
        string? inputPath,
        string? outputPath)
    {
        var callbacks = new CliPluginCallbacks();

        if (passphrase)
        {
            if (recipients.Count > 0 || recipientFiles.Count > 0 || identityFiles.Count > 0)
            {
                Error("-p/--passphrase can't be combined with other recipient flags");
                return 1;
            }

            var pass = ReadPassphrase("Enter passphrase (leave empty to autogenerate): ");
            if (pass.Length == 0)
            {
                pass = GeneratePassphrase();
                Console.Error.WriteLine($"using auto-generated passphrase \"{pass}\"");
            }
            else
            {
                var confirm = ReadPassphrase("Confirm passphrase: ");
                if (pass != confirm)
                {
                    Error("passphrases didn't match");
                    return 1;
                }
            }

            recipients.Add(new ScryptRecipient(pass));
        }
        else
        {
            // Parse recipients from -R files
            foreach (var file in recipientFiles)
            {
                var text = File.ReadAllText(file);
                var parsed = AgeKeygen.ParseRecipientsFile(text, callbacks);
                recipients.AddRange(parsed);
            }

            // Extract recipients from -i identity files (for encrypt mode)
            foreach (var file in identityFiles)
            {
                var identities = LoadIdentities(file, callbacks);
                foreach (var id in identities)
                {
                    switch (id)
                    {
                        case X25519Identity x:
                            recipients.Add(x.Recipient);
                            break;
                        case MlKem768X25519Identity pq:
                            recipients.Add(pq.Recipient);
                            break;
                        case SshEd25519Identity ssh:
                            recipients.Add(ssh.Recipient);
                            break;
                        case SshRsaIdentity ssh:
                            recipients.Add(ssh.Recipient);
                            break;
                        default:
                            Console.Error.WriteLine($"warning: skipping identity without public recipient extraction (plugin identity)");
                            break;
                    }
                }
            }

            if (recipients.Count == 0)
            {
                Error("missing recipients (-r, -R, or -i required for encryption)");
                PrintUsage();
                return 1;
            }
        }

        // Safety check: refuse binary output to terminal
        if (outputPath is null && !armor && Console.IsOutputRedirected == false)
        {
            Error("refusing to output binary to a terminal. Did you mean to use -a/--armor?");
            return 1;
        }

        using var input = OpenInput(inputPath);
        using var output = OpenOutput(outputPath);
        AgeEncrypt.Encrypt(input, output, armor, [.. recipients]);
        return 0;
    }

    private static int Decrypt(
        List<string> identityFiles,
        bool passphrase,
        string? inputPath,
        string? outputPath)
    {
        var callbacks = new CliPluginCallbacks();
        var identities = new List<IIdentity>();

        if (passphrase)
        {
            if (identityFiles.Count > 0)
            {
                Error("-p/--passphrase can't be combined with -i/--identity");
                return 1;
            }

            identities.Add(new LazyPassphraseIdentity());
        }
        else
        {
            if (identityFiles.Count == 0)
            {
                Error("missing identity (-i required for decryption, or use -p for passphrase)");
                return 1;
            }

            foreach (var file in identityFiles)
            {
                var loaded = LoadIdentities(file, callbacks);
                foreach (var id in loaded)
                    identities.Add(id is ScryptRecipient ? new RejectScryptIdentity() : id);
            }
        }

        // Buffer input into a seekable MemoryStream so armor auto-detection works
        using var rawInput = OpenInput(inputPath);
        using var input = new MemoryStream();
        rawInput.CopyTo(input);
        input.Position = 0;

        using var output = OpenOutput(outputPath);
        AgeEncrypt.Decrypt(input, output, [.. identities]);
        return 0;
    }

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
        {
            return [AgeKeygen.ParseSshIdentity(text)];
        }

        // Standard age identity file (AGE-SECRET-KEY-, AGE-SECRET-KEY-PQ-, AGE-PLUGIN-)
        return [.. AgeKeygen.ParseIdentityFile(text, callbacks)];
    }

    private static string ReadPassphrase(string prompt)
    {
        Console.Error.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                return sb.ToString();
            }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                sb.Remove(sb.Length - 1, 1);
            else if (key.KeyChar != '\0')
                sb.Append(key.KeyChar);
        }
    }

    private static string GeneratePassphrase()
    {
        // Simple random passphrase: 10 groups of lowercase letters
        var rng = new Random();
        var parts = new string[10];
        for (int i = 0; i < 10; i++)
        {
            var chars = new char[6];
            for (int j = 0; j < 6; j++)
                chars[j] = (char)('a' + rng.Next(26));
            parts[i] = new string(chars);
        }
        return string.Join("-", parts);
    }

    private static Stream OpenInput(string? path)
    {
        if (path is null)
            return Console.OpenStandardInput();
        return File.OpenRead(path);
    }

    private static Stream OpenOutput(string? path)
    {
        if (path is null)
            return Console.OpenStandardOutput();
        return new LazyFileStream(path);
    }

    private static void Error(string message)
    {
        Console.Error.WriteLine($"age: {message}");
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("""
            Usage:
                age [--encrypt] -r RECIPIENT [-r ...] [-a] [-o OUTPUT] [INPUT]
                age [--encrypt] -R PATH [-R ...] [-a] [-o OUTPUT] [INPUT]
                age [--encrypt] -i IDENTITY [-i ...] [-a] [-o OUTPUT] [INPUT]
                age [--encrypt] -p [-a] [-o OUTPUT] [INPUT]
                age --decrypt [-i IDENTITY | -p] [-o OUTPUT] [INPUT]

            Options:
                -e, --encrypt          Encrypt the input (default)
                -d, --decrypt          Decrypt the input
                -o, --output PATH      Write output to PATH
                -a, --armor            Use ASCII armored format
                -p, --passphrase       Use passphrase-based encryption
                -r, --recipient REC    Encrypt to recipient REC (can be repeated)
                -R, --recipients-file  Path to a file with recipients (can be repeated)
                -i, --identity PATH    Path to an identity file (can be repeated)
                    --version          Print version
                -h, --help             Print this help

            Recipient types:
                age1...                X25519
                age1pq...              ML-KEM-768-X25519 (post-quantum)
                age1<name>1...         Plugin (age-plugin-<name>)
                ssh-ed25519 ...        SSH Ed25519
                ssh-rsa ...            SSH RSA

            INPUT defaults to stdin, and OUTPUT defaults to stdout.
            """);
    }

    /// <summary>
    /// A passphrase identity that lazily prompts the user on first use.
    /// Used for <c>age -d -p</c> mode.
    /// </summary>
    private sealed class LazyPassphraseIdentity : IIdentity
    {
        private ScryptRecipient? _inner;

        public byte[]? Unwrap(Format.Stanza stanza)
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
        public byte[]? Unwrap(Format.Stanza stanza)
        {
            if (stanza.Type == "scrypt")
                throw new AgeException("passphrase-encrypted file can't be decrypted with -i; use -p instead");
            return null;
        }
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
        public override long Position { get => Inner.Position; set => Inner.Position = value; }
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
        public void DisplayMessage(string message) => Console.Error.WriteLine(message);

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
