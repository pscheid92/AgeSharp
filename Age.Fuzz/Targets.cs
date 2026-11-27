using System.Text;
using AgeSharp;

namespace Age.Fuzz;

/// <summary>An oracle that failed: what kind of failure, and the details.</summary>
internal sealed class Finding(string kind, string message) : Exception(message)
{
    public string Kind { get; } = kind;
}

/// <summary>A fuzz target: runs one input, returning its outcome as a short signature.</summary>
internal sealed record Target(Func<byte[], string> Run, Func<IEnumerable<byte[]>> Seeds);

/// <summary>
/// The targets. Each allows only the exceptions its entry point documents; anything else
/// propagates, and the worker saves it as a finding. Some check more: see each one.
/// </summary>
internal static class Targets
{
    public static readonly string[] Names =
        ["header", "armor", "decrypt", "identities", "recipients", "ssh", "sshpub", "identity-file", "plugin", "plugin-client"];

    private static readonly byte[] FileKey = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];

    public static Target Create(string name, string repo) => name switch
    {
        "header" => new(data => Outcomes.Expect<AgeFormatException>(() => AgeHeader.Read(new MemoryStream(data))), () => Seeds.Files(repo)),
        "armor" => new(data => Outcomes.Expect<AgeFormatException>(() => Armor.Decode(new MemoryStream(data), new MemoryStream())), () => Seeds.ArmoredFiles(repo)),
        "decrypt" => DecryptTarget.Create(repo),
        "identities" => new(IdentityLines, () => Seeds.IdentityFiles(repo)),
        "recipients" => new(RecipientLines, () => Seeds.RecipientFiles(repo)),
        "ssh" => new(Ssh, () => Seeds.SshKeys(repo)),
        "sshpub" => new(SshPublic, () => Seeds.SshPublicBlobs(repo)),
        "identity-file" => new(IdentityFile, () => Seeds.EncryptedIdentityFiles(repo)),
        "plugin" => new(PluginTargets.Server, () => PluginTargets.Seeds().Server),
        "plugin-client" => new(PluginTargets.Client, () => PluginTargets.Seeds().Client),
        _ => throw new ArgumentException($"unknown target \"{name}\"; targets: {string.Join(", ", Names)}"),
    };

    // An identity file; every identity in it must open what its own recipient wraps.
    private static string IdentityLines(byte[] data) => Outcomes.Expect<FormatException>(() =>
    {
        using var parsed = Identities.Parse(Encoding.UTF8.GetString(data));
        foreach (var identity in parsed)
            RoundTrip(identity);
    });

    // A recipients file; whatever parses must encrypt, unless the recipients cannot be combined.
    private static string RecipientLines(byte[] data) => Outcomes.Expect<FormatException>(() =>
    {
        var parsed = Recipients.Parse(Encoding.UTF8.GetString(data));
        if (parsed.Any(r => r is PluginRecipient))
            return;
        try
        {
            _ = parsed.Encrypt("fuzz"u8);
        }
        catch (AgeException)
        {
            // Recipients with different labels, or a passphrase among others.
        }
    });

    // An SSH private key; one the passphrase opens must open what its recipient wraps.
    private static string Ssh(byte[] data) => Outcomes.Expect<FormatException>(() =>
    {
        var identity = SshIdentity.Parse(Encoding.UTF8.GetString(data), () => "hunter2".ToCharArray());
        try
        {
            RoundTrip(identity);
        }
        catch (AgeException)
        {
            // A wrong passphrase, or a key the passphrase does not open.
        }
        finally
        {
            ((IDisposable)identity).Dispose();
        }
    });

    // An SSH public key blob, as ssh-ed25519 and as ssh-rsa; one that parses must wrap.
    private static string SshPublic(byte[] data)
    {
        var b64 = Convert.ToBase64String(data);
        var ed25519 = Outcomes.Expect<FormatException>(() => Recipients.ParseOne("ssh-ed25519 " + b64).Wrap(FileKey));
        var rsa = Outcomes.Expect<FormatException>(() => Recipients.ParseOne("ssh-rsa " + b64).Wrap(FileKey));
        return ed25519 == "ok" || rsa == "ok" ? "ok" : ed25519 + " | " + rsa;
    }

    // A passphrase-encrypted identity file; one that opens must open what its recipients wrap.
    // Inputs whose scrypt work factor is above 12 are passed over: the file allows up to 22,
    // which takes seconds an input, so they would only be reported as hangs.
    private static string IdentityFile(byte[] data)
    {
        try
        {
            var header = AgeHeader.Read(new MemoryStream(data));
            if (header.Stanzas.Any(s => s.Type == "scrypt" && s.Args.Count == 2 && int.TryParse(s.Args[1], out var w) && w > 12))
                return "passed over: work factor above 12";
        }
        catch (AgeFormatException)
        {
            // The file itself reports it.
        }

        return Outcomes.Expect<AgeException>(() =>
        {
            using var file = new EncryptedIdentityFile(data, () => "fuzz".ToCharArray());
            foreach (var recipient in file.GetRecipients())
            {
                if (recipient is PluginRecipient)
                    continue;
                var opened = new byte[FileKey.Length];
                if (!((IIdentity)file).TryUnwrap(recipient.Wrap(FileKey), opened) || !opened.AsSpan().SequenceEqual(FileKey))
                    throw new Finding("round trip", $"the file does not open what its recipient {recipient} wraps");
            }
        });
    }

    /// <summary>An identity with a recipient must open what that recipient wraps.</summary>
    public static void RoundTrip(IIdentity identity)
    {
        if (identity is not IIdentityWithRecipient withRecipient || identity is PluginIdentity)
            return;
        var opened = new byte[FileKey.Length];
        if (!identity.TryUnwrap(withRecipient.Recipient.Wrap(FileKey), opened) || !opened.AsSpan().SequenceEqual(FileKey))
            throw new Finding("round trip", $"{identity} does not open what its own recipient wraps");
    }
}

/// <summary>Outcome signatures.</summary>
internal static class Outcomes
{
    /// <summary>"ok", or the shape of the allowed exception <typeparamref name="T"/>.</summary>
    public static string Expect<T>(Action act) where T : Exception
    {
        try
        {
            act();
            return "ok";
        }
        catch (T ex)
        {
            return Shape(ex);
        }
    }

    /// <summary>
    /// The exception's type and the plain words that open its message — none of the bytes,
    /// names, lengths or positions it quotes, which would make every mutant an outcome of its
    /// own — and the same for what a wrapping FormatException wraps.
    /// </summary>
    public static string Shape(Exception ex)
    {
        var shape = ex.GetType().Name + ": " + Words(ex.Message);
        return ex is FormatException && ex.InnerException is { } inner ? shape + " / " + Shape(inner) : shape;
    }

    /// <summary>The plain lowercase words that open a message, up to the first quote or colon.</summary>
    public static string Words(string message)
    {
        var lead = message.Split(':', '"', '\'', '(', ',', ';', '`', '\n')[0];
        var words = lead.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(w => w.TrimEnd('.'))
            .Where(w => w.Length > 0 && w.All(c => c is >= 'a' and <= 'z' or '-'));
        var text = string.Join(' ', words);
        return text.Length > 40 ? text[..40] : text;
    }
}
