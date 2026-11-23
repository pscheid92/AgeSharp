using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

/// <summary>
/// The plugin side of the age plugin protocol, for writing an <c>age-plugin-&lt;name&gt;</c>
/// binary in .NET. A plugin exposes ordinary recipients and identities: it registers how to make
/// them from the data in its keys, and <see cref="Run(string[])"/> speaks the protocol around
/// them for any age client (go-age, rage, AgeSharp). It mirrors go-age's <c>plugin.Plugin</c>.
/// </summary>
/// <remarks>
/// <para>
/// A plugin named <c>frood</c> is the binary <c>age-plugin-frood</c>, its recipients are
/// <c>age1frood1…</c> and its identities <c>AGE-PLUGIN-FROOD-1…</c>; the handlers receive the
/// Bech32 data of a key, its name already checked. Recipients and identities may talk to the
/// user through the client while they wrap or unwrap (<see cref="DisplayMessage"/>,
/// <see cref="RequestValue"/>, <see cref="RequestSecret"/>, <see cref="Confirm"/>).
/// </para>
/// <para>
/// An exception from a handler, a <c>Wrap</c> or a <c>TryUnwrap</c> is reported to the client
/// as that key's error, with its message; an identity that returns false is simply not the one
/// for that file. An instance runs one session at a time.
/// </para>
/// </remarks>
public sealed class AgePlugin
{
    private const string RecipientV1 = "recipient-v1";
    private const string IdentityV1 = "identity-v1";

    private Func<byte[], IRecipient>? _recipient;
    private Func<byte[], IRecipient>? _identityAsRecipient;
    private Func<byte[], IIdentity>? _identity;

    // The session's channel, set while Run speaks the protocol; and whether the recipients and
    // identities may talk to the user, which they may only from their Wrap or TryUnwrap.
    private StanzaChannel? _channel;
    private TextWriter _stderr = TextWriter.Null;
    private bool _interacting;

    // The protocol broke while a recipient or identity talked to the user: whatever it does next,
    // the session is over.
    private bool _broken;

    /// <summary>Creates a plugin with the given name, which is case-insensitive.</summary>
    /// <param name="name">The name: <c>frood</c> for the binary <c>age-plugin-frood</c>.</param>
    /// <exception cref="ArgumentException">The name is empty or has a character other than ASCII letters, digits, <c>+</c>, <c>-</c>, <c>.</c> and <c>_</c>.</exception>
    public AgePlugin(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (!PluginNameValidator.IsValid(name))
            throw new ArgumentException($"invalid plugin name: '{name}'", nameof(name));

        Name = name.ToLowerInvariant();
    }

    /// <summary>The plugin's name, in lowercase.</summary>
    public string Name { get; }

    /// <summary>
    /// Registers how to make a recipient from the data of an <c>age1&lt;name&gt;1…</c>
    /// recipient, for recipient-v1. A recipient that implements <see cref="IRecipientWithLabels"/>
    /// has its labels passed on; a client that does not take labels gets that key's error instead,
    /// as from rage's plugins, so a labelled stanza is never mixed with others unchecked.
    /// </summary>
    /// <remarks>Each call is handed an array of its own, which the handler may keep.</remarks>
    /// <exception cref="InvalidOperationException">A recipient handler is already registered.</exception>
    public void HandleRecipient(Func<byte[], IRecipient> parse) =>
        _recipient = Register(_recipient, parse);

    /// <summary>
    /// Registers how to make a recipient from the data of an <c>AGE-PLUGIN-&lt;NAME&gt;-1…</c>
    /// identity, for recipient-v1: what lets a client encrypt to one of this plugin's identities
    /// (see <see cref="PluginIdentity.Recipient"/>).
    /// </summary>
    /// <remarks>
    /// The data is an identity's, so it may be secret. Each call is handed an array of its own,
    /// which the handler owns and should clear once the recipient no longer needs it.
    /// </remarks>
    /// <exception cref="InvalidOperationException">An identity-as-recipient handler is already registered.</exception>
    public void HandleIdentityAsRecipient(Func<byte[], IRecipient> parse) =>
        _identityAsRecipient = Register(_identityAsRecipient, parse);

    /// <summary>
    /// Registers how to make an identity from the data of an <c>AGE-PLUGIN-&lt;NAME&gt;-1…</c>
    /// identity, for identity-v1. The identities it makes are disposed when the session ends.
    /// </summary>
    /// <remarks>
    /// Each call is handed an array of its own, which the handler owns: AgePlugin does not clear
    /// it, since the identity may keep it. An identity that does should clear it when disposed;
    /// one that does not can clear it once it has what it needs.
    /// </remarks>
    /// <exception cref="InvalidOperationException">An identity handler is already registered.</exception>
    public void HandleIdentity(Func<byte[], IIdentity> parse) =>
        _identity = Register(_identity, parse);

    private static T Register<T>(T? current, T parse) where T : Delegate
    {
        ArgumentNullException.ThrowIfNull(parse);

        return current is null ? parse : throw new InvalidOperationException("the handler is already registered");
    }

    /// <summary>The recipient <c>age1&lt;name&gt;1…</c> that carries <paramref name="data"/>.</summary>
    public string EncodeRecipient(ReadOnlySpan<byte> data) =>
        Bech32.Encode($"age1{Name}", data);

    /// <summary>
    /// The identity <c>AGE-PLUGIN-&lt;NAME&gt;-1…</c> that carries <paramref name="data"/>.
    /// Handle the result as a secret if the data is one.
    /// </summary>
    public string EncodeIdentity(ReadOnlySpan<byte> data) =>
        Bech32.Encode($"age-plugin-{Name}-", data).ToUpperInvariant();

    /// <summary>
    /// Runs the state machine that <paramref name="args"/> names
    /// (<c>--age-plugin=recipient-v1</c> or <c>--age-plugin=identity-v1</c>, as clients launch a
    /// plugin) over standard input and output, and returns the exit code to end the process with.
    /// </summary>
    /// <remarks>
    /// The exit codes are go-age's: 0 when the session completed (an identity that matched
    /// nothing included), 1 when the protocol failed, 2 when it broke while a recipient or
    /// identity talked to the user, 3 when a recipient or identity failed and the client was
    /// told, 4 when no known state machine was named. Other arguments are the plugin's own: a
    /// plugin that takes some, to generate keys say, handles them before calling this.
    /// </remarks>
    public int Run(string[] args) =>
        Run(args, Console.OpenStandardInput(), Console.OpenStandardOutput(), Console.Error);

    internal int Run(string[] args, Stream input, Stream output, TextWriter stderr)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (_channel is not null)
            throw new InvalidOperationException("the plugin is already running a session");

        _stderr = stderr;
        _broken = false;

        var stateMachine = StateMachine(args);

        if (stateMachine is not (RecipientV1 or IdentityV1))
            return Fatal($"unknown state machine \"{stateMachine}\"", code: 4);

        using var reader = new StreamReader(input, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        _channel = new StanzaChannel(reader, output, peer: "client");

        try
        {
            return stateMachine == RecipientV1 ? RunRecipientV1() : RunIdentityV1();
        }
        catch (Protocol ex)
        {
            return Fatal(ex.Message);
        }
        catch (AgePluginException ex)
        {
            // The client wrote something that is not a stanza.
            return Fatal(ex.Message);
        }
        catch (IOException ex)
        {
            return Fatal($"the client went away: {ex.Message}");
        }
        finally
        {
            _channel = null;
            _interacting = false;
        }
    }

    // --- recipient-v1 -------------------------------------------------------------------------

    private int RunRecipientV1()
    {
        if (_recipient is null && _identityAsRecipient is null)
            return Fatal($"{RecipientV1} not supported");

        List<string> recipientStrings = [], identityStrings = [];
        List<byte[]> fileKeys = [];
        var supportsLabels = false;

        try
        {
            foreach (var (type, args, body) in ReadPhaseOne())
            {
                switch (type)
                {
                    case "add-recipient":
                        ExpectNoBody(type, args, body, 1);
                        recipientStrings.Add(args[0]);
                        break;
                    case "add-identity":
                        ExpectNoBody(type, args, body, 1);
                        identityStrings.Add(args[0]);
                        break;
                    case "extension-labels":
                        ExpectNoBody(type, args, body, 0);
                        supportsLabels = true;
                        break;
                    case "wrap-file-key":
                        ExpectBody(type, args, body, 0);
                        fileKeys.Add(body);
                        break;
                }
            }

            if (recipientStrings.Count + identityStrings.Count == 0)
                return Fatal("no recipients or identities provided");

            if (fileKeys.Count == 0)
                return Fatal("no file keys provided");

            return WrapAll(recipientStrings, identityStrings, fileKeys, supportsLabels);
        }
        finally
        {
            foreach (var fileKey in fileKeys)
                CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    private int WrapAll(List<string> recipientStrings, List<string> identityStrings, List<byte[]> fileKeys, bool supportsLabels)
    {
        // Each key, as what reports its errors: "recipient N" or "identity N".
        var keys = new List<(string Kind, int Index, IRecipient Recipient)>();

        try
        {
            for (var i = 0; i < recipientStrings.Count; i++)
            {
                if (!TryParse(recipientStrings[i], "recipient", i, ParseRecipientData, _recipient, "recipient encodings not supported", out var recipient, out var code))
                    return code;

                keys.Add(("recipient", i, recipient));
            }

            for (var i = 0; i < identityStrings.Count; i++)
            {
                if (!TryParse(identityStrings[i], "identity", i, ParseIdentityData, _identityAsRecipient, "identity encodings not supported", out var recipient, out var code))
                    return code;

                keys.Add(("identity", i, recipient));
            }

            // The labels are the first key's, and every other key must have the same: one file
            // never mixes keys with different ones. As in go-age, the plugin declares them once,
            // for every file key.
            string[]? labels = null;
            var stanzas = new List<Stanza>[fileKeys.Count];

            for (var f = 0; f < fileKeys.Count; f++)
            {
                stanzas[f] = [];

                foreach (var (kind, index, recipient) in keys)
                {
                    LabelledStanzas wrapped;

                    try
                    {
                        wrapped = Interacting(() => recipient is IRecipientWithLabels labelled
                            ? labelled.WrapWithLabels(fileKeys[f])
                            : new LabelledStanzas(recipient.Wrap(fileKeys[f]), []));
                    }
                    catch (Exception ex)
                    {
                        // Once the session broke, whatever the recipient made of it (let it
                        // through, wrapped it) ends the session: the client cannot be told.
                        return _broken ? 2 : KeyError(kind, index, ex.Message);
                    }

                    if (_broken)
                        return 2;

                    var these = wrapped.Labels ?? [];

                    if (InvalidLabels(these) is { } invalid)
                        return KeyError(kind, index, invalid);

                    // A client that does not take labels would mix this key with any other, which
                    // is what labels exist to prevent: refused, as rage's plugins refuse it.
                    if (these.Count > 0 && !supportsLabels)
                        return KeyError(kind, index, "the recipient has security labels, and the client does not support labels");

                    if (labels is null)
                        labels = [.. these];
                    else if (!SameLabels(labels, these))
                        return KeyError(kind, index, $"labels {Quoted(these)} do not match previous recipients {Quoted(labels)}");

                    // As the client refuses for any recipient: a key left out of the file is
                    // not something to do silently. Null, a default LabelledStanzas, is the same.
                    if (wrapped.Stanzas is not { Count: > 0 })
                        return KeyError(kind, index, $"recipient {recipient.GetType().Name} produced no stanzas");

                    stanzas[f].AddRange(wrapped.Stanzas);
                }
            }

            if (supportsLabels)
            {
                // Set by the first key: there is at least one key and one file key by now.
                Write("labels", labels!, []);
                ExpectOk();
            }

            for (var f = 0; f < stanzas.Length; f++)
            {
                foreach (var stanza in stanzas[f])
                {
                    Write("recipient-stanza", [f.ToString(System.Globalization.CultureInfo.InvariantCulture), stanza.Type, .. stanza.Args], stanza.Body.ToArray());
                    ExpectOk();
                }
            }

            Write("done", [], []);
            return 0;
        }
        finally
        {
            foreach (var (_, _, recipient) in keys)
                (recipient as IDisposable)?.Dispose();
        }
    }

    // Labels are sent as stanza arguments, which the protocol requires to be VCHAR strings, and
    // it forbids duplicates (age-plugin.md: "Plugins MUST NOT send duplicate labels").
    private static string? InvalidLabels(IReadOnlyCollection<string> labels)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
                return "a label is empty";

            if (Stanza.IndexOfNonVChar(label) >= 0)
                return $"label \"{label}\" has a character other than printable ASCII";

            if (!seen.Add(label))
                return $"label \"{label}\" is declared twice";
        }

        return null;
    }

    private static bool SameLabels(IEnumerable<string> a, IEnumerable<string> b) =>
        a.ToHashSet(StringComparer.Ordinal).SetEquals(b);

    private static string Quoted(IEnumerable<string> labels) =>
        $"[{string.Join(", ", labels.Select(l => $"\"{l}\""))}]";

    // --- identity-v1 --------------------------------------------------------------------------

    private int RunIdentityV1()
    {
        if (_identity is null)
            return Fatal($"{IdentityV1} not supported");

        List<string> identityStrings = [];
        List<List<Stanza>> files = [];

        foreach (var (type, args, body) in ReadPhaseOne())
        {
            switch (type)
            {
                case "add-identity":
                    ExpectNoBody(type, args, body, 1);
                    identityStrings.Add(args[0]);
                    break;

                case "recipient-stanza":
                    if (args.Length < 2)
                        throw new Protocol($"recipient-stanza stanza has {args.Length} arguments, want >=2");

                    if (!int.TryParse(args[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var index))
                        throw new Protocol($"failed to parse recipient-stanza stanza argument: {args[0]}");

                    var stanza = new Stanza(args[1], args[2..], body);

                    // Stanzas arrive file by file: the next file's index, or the current one's.
                    if (index == files.Count)
                        files.Add([stanza]);
                    else if (index == files.Count - 1)
                        files[^1].Add(stanza);
                    else
                        throw new Protocol($"unexpected file index {index}, previous was {files.Count - 1}");

                    break;
            }
        }

        if (identityStrings.Count == 0)
            return Fatal("no identities provided");

        if (files.Count == 0)
            return Fatal("no stanzas provided");

        var identities = new List<IIdentity>();

        try
        {
            for (var i = 0; i < identityStrings.Count; i++)
            {
                if (!TryParse(identityStrings[i], "identity", i, ParseIdentityData, _identity, "identity encodings not supported", out var identity, out var code))
                    return code;

                identities.Add(identity);
            }

            for (var f = 0; f < files.Count; f++)
            {
                var code = UnwrapFile(f, files[f], identities);

                if (code != 0)
                    return code;
            }

            Write("done", [], []);
            return 0;
        }
        finally
        {
            foreach (var identity in identities)
                identity.Dispose();
        }
    }

    // The first identity that opens the file sends its key; one that fails is the file's error,
    // and the session goes on with the next file, as the protocol allows.
    private int UnwrapFile(int file, List<Stanza> stanzas, List<IIdentity> identities)
    {
        var fileKey = new byte[AgeSharp.FileKey.Size];

        try
        {
            foreach (var identity in identities)
            {
                bool unwrapped;

                try
                {
                    unwrapped = Interacting(() => identity.TryUnwrap(stanzas, fileKey));
                }
                catch (Exception ex)
                {
                    // As for a recipient: once the session broke, it ends, however the identity
                    // handled the exception.
                    if (_broken)
                        return 2;

                    Write("error", ["stanza", file.ToString(System.Globalization.CultureInfo.InvariantCulture), "0"], Encoding.UTF8.GetBytes(ex.Message));
                    ExpectOk();
                    return 0;
                }

                if (_broken)
                    return 2;

                if (!unwrapped)
                    continue;

                Write("file-key", [file.ToString(System.Globalization.CultureInfo.InvariantCulture)], fileKey);
                ExpectOk();
                return 0;
            }

            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    // --- Talking to the user ------------------------------------------------------------------

    /// <summary>
    /// Asks the client to show the user a message, which by convention starts in lowercase and
    /// has no final period. It may return before the message is shown.
    /// </summary>
    /// <exception cref="AgePluginException">The client could not show it, or the protocol broke.</exception>
    /// <exception cref="InvalidOperationException">Not called from a recipient's Wrap or an identity's TryUnwrap during <see cref="Run(string[])"/>.</exception>
    public void DisplayMessage(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var reply = Ask("msg", [], Encoding.UTF8.GetBytes(message), "client failed to display message");
        ExpectNoBody(reply, 0, interactive: true);
    }

    /// <summary>Asks the user, through the client, for a value that is not secret.</summary>
    /// <exception cref="AgePluginException">The client could not ask, the user declined, or the protocol broke.</exception>
    /// <exception cref="InvalidOperationException">Not called from a recipient's Wrap or an identity's TryUnwrap during <see cref="Run(string[])"/>.</exception>
    public string RequestValue(string prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        var reply = Ask("request-public", [], Encoding.UTF8.GetBytes(prompt), "client failed to request value");
        ExpectArgs(reply, 0, interactive: true);
        return Encoding.UTF8.GetString(reply.Body);
    }

    /// <summary>
    /// Asks the user, through the client, for a secret such as a PIN. The caller owns the result
    /// and should clear it once used.
    /// </summary>
    /// <exception cref="AgePluginException">The client could not ask, the user declined, or the protocol broke.</exception>
    /// <exception cref="InvalidOperationException">Not called from a recipient's Wrap or an identity's TryUnwrap during <see cref="Run(string[])"/>.</exception>
    public char[] RequestSecret(string prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        var reply = Ask("request-secret", [], Encoding.UTF8.GetBytes(prompt), "client failed to request value");

        try
        {
            ExpectArgs(reply, 0, interactive: true);
            return Encoding.UTF8.GetChars(reply.Body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(reply.Body);
        }
    }

    /// <summary>
    /// Asks the user, through the client, to choose between <paramref name="yes"/> and, when
    /// given, <paramref name="no"/>: true when they chose yes. An empty <paramref name="no"/> is
    /// no option, as go-age reads it.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="yes"/> is empty.</exception>
    /// <exception cref="AgePluginException">The client could not ask, or the protocol broke.</exception>
    /// <exception cref="InvalidOperationException">Not called from a recipient's Wrap or an identity's TryUnwrap during <see cref="Run(string[])"/>.</exception>
    public bool Confirm(string message, string yes, string? no = null)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrEmpty(yes);

        string[] options = string.IsNullOrEmpty(no)
            ? [Base64Unpadded.Encode(Encoding.UTF8.GetBytes(yes))]
            : [Base64Unpadded.Encode(Encoding.UTF8.GetBytes(yes)), Base64Unpadded.Encode(Encoding.UTF8.GetBytes(no))];

        var reply = Ask("confirm", options, Encoding.UTF8.GetBytes(message), "client failed to request confirmation");
        ExpectNoBody(reply, 1, interactive: true);
        return reply.Args[0] == "yes";
    }

    // Sends a request and reads the ok or fail it is answered with. A fail is the client's
    // refusal; anything else breaks the session.
    private (string Type, string[] Args, byte[] Body) Ask(string type, string[] args, byte[] body, string refused)
    {
        if (_channel is null || !_interacting)
            throw new InvalidOperationException("the plugin can talk to the user only from a recipient's Wrap or an identity's TryUnwrap, while it runs");

        if (_broken)
            throw new AgePluginException("the plugin session is broken");

        (string Type, string[] Args, byte[] Body) reply;

        try
        {
            _channel.Write(type, args, body);
            reply = _channel.Read() ?? throw new Protocol("failed to read response stanza: the client went away");
        }
        catch (Exception ex) when (ex is Protocol or AgePluginException or IOException)
        {
            throw Broke(ex.Message);
        }

        switch (reply.Type)
        {
            case "fail":
                ExpectNoBody(reply, 0, interactive: true);
                throw new AgePluginException(refused);
            case "ok":
                return reply;
            case "unsupported":
                // The client does not know the request: a refusal, as rage reads it, which the
                // plugin may get past; not a broken session.
                ExpectNoBody(reply, 0, interactive: true);
                throw new AgePluginException($"{refused}: the client does not support it");
            default:
                throw Broke($"expected ok or fail stanza, got \"{reply.Type}\"");
        }
    }

    private T Interacting<T>(Func<T> act)
    {
        _interacting = true;

        try
        {
            return act();
        }
        finally
        {
            _interacting = false;
        }
    }

    private AgePluginException Broke(string message)
    {
        _broken = true;
        _stderr.WriteLine(message);
        return new AgePluginException(message);
    }

    // --- Wire ---------------------------------------------------------------------------------

    // Phase one is the client's: everything up to its done. Stanzas a plugin does not know are
    // ignored there, as the protocol says.
    private IEnumerable<(string Type, string[] Args, byte[] Body)> ReadPhaseOne()
    {
        while (true)
        {
            var stanza = _channel!.Read() ?? throw new Protocol("failed to read stanza: the client went away");

            if (stanza.Type == "done")
            {
                ExpectNoBody(stanza.Type, stanza.Args, stanza.Body, 0);
                yield break;
            }

            yield return stanza;
        }
    }

    private void Write(string type, string[] args, byte[] body) =>
        _channel!.Write(type, args, body);

    private void ExpectOk()
    {
        var reply = _channel!.Read() ?? throw new Protocol("failed to read OK stanza: the client went away");

        if (reply.Type != "ok")
            throw new Protocol($"expected OK stanza, got \"{reply.Type}\"");

        ExpectNoBody(reply.Type, reply.Args, reply.Body, 0);
    }

    private void ExpectNoBody((string Type, string[] Args, byte[] Body) s, int args, bool interactive)
    {
        ExpectArgs(s, args, interactive);

        if (s.Body.Length != 0)
            throw Wrong($"{s.Type} stanza has {s.Body.Length} bytes of body, want 0", interactive);
    }

    private void ExpectArgs((string Type, string[] Args, byte[] Body) s, int args, bool interactive)
    {
        if (s.Args.Length != args)
            throw Wrong($"{s.Type} stanza has {s.Args.Length} arguments, want {args}", interactive);
    }

    private Exception Wrong(string message, bool interactive) =>
        interactive ? Broke(message) : new Protocol(message);

    private static void ExpectNoBody(string type, string[] args, byte[] body, int wantArgs)
    {
        ExpectArgs(type, args, wantArgs);

        if (body.Length != 0)
            throw new Protocol($"{type} stanza has {body.Length} bytes of body, want 0");
    }

    private static void ExpectBody(string type, string[] args, byte[] body, int wantArgs)
    {
        ExpectArgs(type, args, wantArgs);

        if (body.Length == 0)
            throw new Protocol($"{type} stanza has 0 bytes of body, want >0");
    }

    private static void ExpectArgs(string type, string[] args, int wantArgs)
    {
        if (args.Length != wantArgs)
            throw new Protocol($"{type} stanza has {args.Length} arguments, want {wantArgs}");
    }

    // --- Keys ---------------------------------------------------------------------------------

    // A key string to the value its handler makes, or the key's error sent and the exit code.
    private bool TryParse<T>(string encoded, string kind, int index, Func<string, (string Name, byte[] Data)> decode,
                             Func<byte[], T>? handler, string unsupported, out T value, out int code) where T : class
    {
        value = null!;
        code = 3;

        try
        {
            var (name, data) = decode(encoded);

            if (name != Name)
                throw new FormatException($"unsupported plugin name: \"{name}\"");

            if (handler is null)
                throw new FormatException(unsupported);

            value = handler(data);
            return true;
        }
        catch (Exception ex)
        {
            code = KeyError(kind, index, ex.Message);
            return false;
        }
    }

    private static (string Name, byte[] Data) ParseRecipientData(string recipient)
    {
        var (hrp, data) = Bech32.Decode(recipient);

        return hrp.StartsWith("age1", StringComparison.Ordinal) && hrp.Length > 4
            ? (hrp[4..], data)
            : throw new FormatException($"invalid recipient encoding \"{recipient}\"");
    }

    private static (string Name, byte[] Data) ParseIdentityData(string identity)
    {
        var (hrp, data) = Bech32.Decode(identity);

        return hrp.StartsWith("age-plugin-", StringComparison.Ordinal) && hrp.EndsWith('-') && hrp.Length > 12
            ? (hrp[11..^1], data)
            : throw new FormatException("invalid identity encoding");
    }

    private int KeyError(string kind, int index, string message)
    {
        Write("error", [kind, index.ToString(System.Globalization.CultureInfo.InvariantCulture)], Encoding.UTF8.GetBytes(message));
        ExpectOk();
        return 3;
    }

    // --- Arguments and failures ---------------------------------------------------------------

    // --age-plugin=NAME or --age-plugin NAME, with one dash or two, as Go's flag package reads them.
    private static string StateMachine(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            var flag = arg.StartsWith("--", StringComparison.Ordinal) ? arg[2..] : arg.StartsWith('-') ? arg[1..] : null;

            if (flag is null)
                continue;

            if (flag.StartsWith("age-plugin=", StringComparison.Ordinal))
                return flag["age-plugin=".Length..];

            if (flag == "age-plugin" && i + 1 < args.Length)
                return args[i + 1];
        }

        return "";
    }

    private int Fatal(string message, int code = 1)
    {
        _stderr.WriteLine(message);
        return code;
    }

    // The client broke the protocol: the session ends with exit code 1.
    private sealed class Protocol(string message) : Exception(message);
}
