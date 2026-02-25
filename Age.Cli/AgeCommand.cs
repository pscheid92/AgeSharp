using System.Text;
using Age.Format;
using Age.Plugin;
using Age.Recipients;

namespace Age.Cli;

internal static class AgeCommand
{
    public static int Run(string[] args)
    {
        try
        {
            return Execute(args);
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

    private record AgeArgs(bool Encrypt, bool Armor, bool Passphrase, List<IRecipient> Recipients, List<string> RecipientFiles, List<string> IdentityFiles, string? OutputPath, string? InputPath);

    private static int Execute(string[] args)
    {
        var parsed = ParseArgs(args);
        if (parsed is null)
            return 0;

        return parsed.Encrypt
            ? Encrypt(parsed)
            : Decrypt(parsed);
    }

    private static AgeArgs? ParseArgs(string[] args)
    {
        var state = new AgeArgState();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help":
                    PrintUsage();
                    return null;
                case "--version":
                    Console.WriteLine("age-sharp v0.1.0");
                    return null;
                default:
                    state.Apply(args, ref i);
                    break;
            }
        }

        return state.ToArgs();
    }

    private sealed class AgeArgState
    {
        private bool _encrypt = true;
        private bool _armor;
        private bool _passphrase;
        private readonly List<IRecipient> _recipients = [];
        private readonly List<string> _recipientFiles = [];
        private readonly List<string> _identityFiles = [];
        private string? _outputPath;
        private string? _inputPath;

        public void Apply(string[] args, ref int i)
        {
            switch (args[i])
            {
                case "-d" or "--decrypt": _encrypt = false; break;
                case "-e" or "--encrypt": _encrypt = true; break;
                case "-a" or "--armor": _armor = true; break;
                case "-p" or "--passphrase": _passphrase = true; break;
                case "-r" or "--recipient": _recipients.Add(ParseRecipient(ReadRequiredArg(args, ref i, "-r"))); break;
                case "-R" or "--recipients-file": _recipientFiles.Add(ReadRequiredArg(args, ref i, "-R")); break;
                case "-i" or "--identity": _identityFiles.Add(ReadRequiredArg(args, ref i, "-i")); break;
                case "-o" or "--output": _outputPath = ReadRequiredArg(args, ref i, "-o"); break;
                default: _inputPath = ParsePositionalArg(args[i], _inputPath); break;
            }
        }

        public AgeArgs ToArgs() =>
            new(_encrypt, _armor, _passphrase, _recipients, _recipientFiles, _identityFiles, _outputPath, _inputPath);
    }

    private static string ReadRequiredArg(string[] args, ref int i, string flag) =>
        ++i < args.Length ? args[i] : throw new AgeException($"flag requires an argument: {flag}");

    private static string ParsePositionalArg(string arg, string? current)
    {
        if (arg.StartsWith('-'))
            throw new AgeException($"unknown option: {arg}");

        return current is not null ? throw new AgeException($"unexpected argument: {arg}") : arg;
    }

    private static int Encrypt(AgeArgs parsed)
    {
        var callbacks = new CliPluginCallbacks();
        var recipients = parsed.Recipients;

        if (parsed.Passphrase)
        {
            if (recipients.Count > 0 || parsed.RecipientFiles.Count > 0 || parsed.IdentityFiles.Count > 0)
                throw new AgeException("-p/--passphrase can't be combined with other recipient flags");

            recipients.Add(new ScryptRecipient(ReadAndConfirmPassphrase()));
        }
        else
        {
            CollectRecipientsFromFiles(parsed, recipients, callbacks);

            if (recipients.Count == 0)
                throw new AgeException("missing recipients (-r, -R, or -i required for encryption)");
        }

        if (parsed.OutputPath is null && !parsed.Armor && !Console.IsOutputRedirected)
            throw new AgeException("refusing to output binary to a terminal. Did you mean to use -a/--armor?");

        using var input = OpenInput(parsed.InputPath);
        using var output = OpenOutput(parsed.OutputPath);
        AgeEncrypt.Encrypt(input, output, parsed.Armor, [.. recipients]);
        return 0;
    }

    private static void CollectRecipientsFromFiles(AgeArgs parsed, List<IRecipient> recipients, IPluginCallbacks callbacks)
    {
        foreach (var file in parsed.RecipientFiles)
        {
            var text = File.ReadAllText(file);
            recipients.AddRange(AgeKeygen.ParseRecipientsFile(text, callbacks));
        }

        foreach (var file in parsed.IdentityFiles)
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

        if (Environment.GetEnvironmentVariable("AGE_PASSPHRASE") is null)
        {
            var confirm = ReadPassphrase("Confirm passphrase: ");
            if (pass != confirm)
                throw new AgeException("passphrases didn't match");
        }

        return pass;
    }

    private static int Decrypt(AgeArgs parsed)
    {
        var identities = CollectDecryptIdentities(parsed);

        // Buffer input into a seekable MemoryStream so armor auto-detection works
        using var rawInput = OpenInput(parsed.InputPath);
        using var input = new MemoryStream();
        rawInput.CopyTo(input);
        input.Position = 0;

        using var output = OpenOutput(parsed.OutputPath);
        AgeEncrypt.Decrypt(input, output, [.. identities]);
        return 0;
    }

    private static List<IIdentity> CollectDecryptIdentities(AgeArgs parsed)
    {
        var callbacks = new CliPluginCallbacks();
        var identities = new List<IIdentity>();

        if (parsed.Passphrase)
        {
            if (parsed.IdentityFiles.Count > 0)
                throw new AgeException("-p/--passphrase can't be combined with -i/--identity");

            identities.Add(new LazyPassphraseIdentity());
        }
        else
        {
            if (parsed.IdentityFiles.Count == 0)
                throw new AgeException("missing identity (-i required for decryption, or use -p for passphrase)");

            foreach (var file in parsed.IdentityFiles)
            {
                var loaded = LoadIdentities(file, callbacks);
                foreach (var id in loaded)
                    identities.Add(id is ScryptRecipient ? new RejectScryptIdentity() : id);
            }
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

    private static void Error(string message) =>
        Console.Error.WriteLine($"age: {message}");

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

                                Subcommands:
                                    age keygen             Generate a new identity (see age keygen -h)
                                    age inspect            Inspect an age-encrypted file

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