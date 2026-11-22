<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, a wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

[![NuGet](https://img.shields.io/nuget/v/AgeSharp)](https://www.nuget.org/packages/AgeSharp)
[![codecov](https://codecov.io/gh/pscheid92/AgeSharp/graph/badge.svg?token=QNXDXPJU8Q)](https://codecov.io/gh/pscheid92/AgeSharp)

[`AgeSharp`](https://github.com/pscheid92/AgeSharp) is a C# implementation of the
[age](https://age-encryption.org) file encryption format, fully interoperable
with the reference [Go implementation](https://github.com/FiloSottile/age) and
other age-compatible tools.

It depends on [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography)
(2.7.0 or later) and [SSH.NET](https://www.nuget.org/packages/SSH.NET), which it uses
to decrypt passphrase-protected SSH keys; both come with the package. It targets .NET 10. A project
that pins an older BouncyCastle gets a NU1605 (package downgrade) error on restore
and needs to raise its pin to 2.7.0.

## Features

- All standard recipient types: X25519, scrypt/passphrase, SSH-Ed25519, SSH-RSA
- **Post-quantum** ML-KEM-768-X25519 hybrid encryption
- **Hardware keys**: tagged P-256 and P-256 + ML-KEM-768 recipients (`age1tag1…`, `age1tagpq1…`), encryption only
- **Plugin protocol** — interoperates with `age-plugin-*` binaries, and writes them (`AgePlugin`)
- Encrypt to multiple recipients
- ASCII armor, detected when decrypting from any stream, pipes and network streams included
- Streaming encryption and decryption across all APIs — memory is bounded
  by a single 64 KiB chunk buffer regardless of input size (1 GiB file uses
  the same working set as a 1 MB file)
- Async throughout: `EncryptAsync`, `DecryptAsync`, `DecryptReaderAsync`, the detached forms
  and the writers read and write the caller's streams asynchronously
- Pull-based streaming (`EncryptReader` / `DecryptReader`) returns a readable
  `Stream` for pipe-and-forget use cases, and push-based streaming
  (`EncryptWriter` / `DecryptWriter`) a writable one, as `GZipStream` does
- Detached header APIs (`EncryptDetached` / `DecryptDetached`)
- Random-access decryption: `DecryptReader` over a seekable binary file returns a seekable
  stream
- Header inspection without decryption (`AgeHeader.Read`)
- Standalone armor conversion (`Armor.Encode` / `Armor.Decode`)
- Encrypted identity files (passphrase-protected), asked for their passphrase only when needed
- Recipients file parsing (`-R` style files with comments)
- File-key extraction and injection (`AgeHeader.ToBytes`, `Identities.UnwrapFileKey`,
  `FileKeyIdentity`), as go-age's `ExtractHeader` and `DecryptHeader`
- Errors that say what went wrong: format or authentication, and, when nothing matched, why
  each identity didn't
- Fully interoperable — files produced by AgeSharp decrypt with `age`, `rage`, and vice versa
- **Runs in Blazor WebAssembly** — automatically uses a managed
  ChaCha20-Poly1305 backend in the browser, where the platform cipher is
  unavailable. The exceptions: of passphrase-protected SSH keys, only ssh-ed25519
  keys protected with `aes256-gcm@openssh.com` or `chacha20-poly1305@openssh.com`
  decrypt there — not `ssh-keygen`'s default AES-CTR, and no ssh-rsa key; an
  unprotected ssh-rsa key that only SSH.NET reads (one BouncyCastle refuses) is
  refused there too; and the tagged recipients' P-256 exchange, constant-time
  elsewhere, runs on BouncyCastle's managed P-256, which is not

## Installation

```sh
dotnet add package AgeSharp
```

## Usage

### Encrypt and decrypt

```csharp
using AgeSharp;

using var identity = X25519Identity.Generate();
var recipient = identity.Recipient;

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
new Recipients(recipient).Encrypt(input, encrypted);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
new Identities(identity).Decrypt(encrypted, decrypted);
```

### Passphrase encryption

```csharp
using var passphrase = new Passphrase("correct-horse-battery-staple");

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
new Recipients(passphrase).Encrypt(input, encrypted);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
new Identities(passphrase).Decrypt(encrypted, decrypted);
```

The same `Passphrase` encrypts and decrypts, and must be a file's only recipient. It keeps only
a UTF-8 copy, which `Dispose` clears; pass a `ReadOnlySpan<char>` you clear yourself where the
passphrase is held for long, since a `string` can't be cleared. Decrypting refuses files that
ask for a work factor above 22, as go-age does; raise it with `MaxWorkFactor`:

```csharp
using var passphrase = new Passphrase(characters) { MaxWorkFactor = 24 };
```

### ASCII armor

```csharp
new Recipients(recipient).Encrypt(input, encrypted, new AgeEncryptOptions { Armor = true });

// -----BEGIN AGE ENCRYPTED FILE-----
// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA...
// -----END AGE ENCRYPTED FILE-----
```

Decrypting needs no flag: armor is recognised by reading ahead, so it works on a stream that
cannot seek, such as a pipe or a network stream.

### Multiple recipients

```csharp
using var alice = X25519Identity.Generate();
using var bob = X25519Identity.Generate();

new Recipients(alice.Recipient, bob.Recipient).Encrypt(input, encrypted);

// Either identity can decrypt
new Identities(bob).Decrypt(encrypted, decrypted);
```

A `Recipients` set is checked once, when it is built: it must not be empty, and a
passphrase can't be combined with other recipients. Recipients that declare different
security labels (post-quantum and classical, say) are refused when encrypting, before
anything is written. The same set can encrypt any number of files.

### Bytes and async

```csharp
var to = new Recipients(recipient);

byte[] sealedValue = to.Encrypt("a secret"u8);                 // small values
await to.EncryptAsync(input, encrypted, cancellationToken: ct); // every read and write is async

using var with = new Identities(identity);
byte[] opened = with.Decrypt(sealedValue);
await with.DecryptAsync(encrypted, decrypted, cancellationToken: ct);
await using var reader = await with.DecryptReaderAsync(encrypted, cancellationToken: ct);
```

### SSH keys

```csharp
var recipient = SshEd25519Recipient.Parse("ssh-ed25519 AAAA...");
var identity = SshEd25519Identity.Parse(File.ReadAllText("/path/to/id_ed25519"));

new Recipients(recipient).Encrypt(input, encrypted);

encrypted.Position = 0;
new Identities(identity).Decrypt(encrypted, decrypted);
```

A passphrase-protected key (OpenSSH format) needs somewhere to get its passphrase
from. It is asked for only when a file addressed to the key is decrypted, and
never for encrypting to the key. Like every passphrase source in AgeSharp, the callback
returns a `char[]`, cleared once used, or null to cancel:

```csharp
var identity = SshIdentity.Parse(
    File.ReadAllText("/path/to/id_ed25519"),
    passphrase: () => PromptForPassphrase());
```

An ssh-rsa key protected in the older PEM format (`BEGIN RSA PRIVATE KEY` with
`Proc-Type: 4,ENCRYPTED`, as `ssh-keygen` wrote before OpenSSH 7.8 and still writes with
`-m PEM`) does not store its public key, so, as with `age`, it needs its `.pub` file
too. The decrypted key must match it:

```csharp
var identity = SshIdentity.Parse(
    File.ReadAllText("/path/to/id_rsa"),
    File.ReadAllText("/path/to/id_rsa.pub"),
    passphrase: () => PromptForPassphrase());
```

Keys encrypted as PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) are not read, as in `age`;
convert them with `ssh-keygen -p`.

### Post-quantum (ML-KEM-768-X25519)

```csharp
using var identity = MlKem768X25519Identity.Generate();
var recipient = identity.Recipient;

new Recipients(recipient).Encrypt(input, encrypted);
```

### Hardware keys (tagged recipients)

age's tagged recipient types are for keys held on hardware, by plugins that use
this format: `age1tag1…` (P-256) and `age1tagpq1…` (P-256 hybridised with
ML-KEM-768, post-quantum). AgeSharp encrypts to them natively; decrypting is done
by the plugin, through `PluginIdentity`.

- Each stanza carries a tag that lets the hardware recognise it, so anyone who knows
  the public key can tell which files were encrypted to it.
- Like `age1pq1…`, an `age1tagpq1…` recipient can't be mixed with classical
  recipients in one file: that would void its post-quantum protection.

```csharp
var recipient = P256TagRecipient.Parse("age1tag1...");
new Recipients(recipient).Encrypt(input, encrypted);

// Recipients files read them too
var recipients = Recipients.Parse(File.ReadAllText("recipients.txt"));
```

### Pull-based streaming

Returns a readable `Stream` — header and key setup is eager, payload encryption/decryption is lazy (chunk-by-chunk on `Read()`).

```csharp
// Encrypt: returns a Stream you read ciphertext from
using var encryptedStream = new Recipients(recipient).EncryptReader(plaintext);
encryptedStream.CopyTo(networkStream);

// Decrypt: returns a Stream you read plaintext from
using var decryptedStream = new Identities(identity).DecryptReader(ciphertext);
decryptedStream.CopyTo(outputStream);
```

### Push-based streaming

Returns a writable `Stream`, as `GZipStream` does: you write plaintext (or an age file) to
it, and it writes the age file (or the plaintext) to the stream you gave it. Disposing it
finishes the file, so dispose it, with `using` or `await using`.

```csharp
// Encrypt: write plaintext, the age file goes to fileStream
await using (var writer = new Recipients(recipient).EncryptWriter(fileStream))
    await source.CopyToAsync(writer);

// Decrypt: write the age file, the plaintext goes to outputStream
using (var writer = new Identities(identity).DecryptWriter(outputStream))
    await response.Content.CopyToAsync(writer);
```

A decrypt writer only knows the file has ended when it is disposed, so that is where the
last chunk is checked and where a truncated file throws: until then, the plaintext written
out is unconfirmed. Once a write fails, a writer fails every later write and finishes nothing.

### Detached headers

Splits the age header and payload into separate streams — useful for storing
the header and payload in different locations.

```csharp
// Encrypt with separate header and payload
new Recipients(recipient).EncryptDetached(input, headerOutput, payloadOutput);

// Decrypt from separate streams
new Identities(identity).DecryptDetached(headerInput, payloadInput, output);
```

### Random-access decryption

When the file is binary and its stream can seek, `DecryptReader` returns a stream that can seek
too: read from any position, and only the chunks a read touches are decrypted. Useful for
encrypted archives, databases and large files.

```csharp
using var file = File.OpenRead("archive.age");
using var plaintext = new Identities(identity).DecryptReader(file);

Console.WriteLine($"Plaintext length: {plaintext.Length}");

plaintext.Seek(50_000, SeekOrigin.Begin);
plaintext.ReadExactly(buffer);
```

- Opening it decrypts the final chunk, so the length is authenticated and a truncated file is
  refused at once.
- A read that fails leaves the position where it was.
- The reader moves the file stream's position, so use one reader per thread.
- Armored files are read front to back, as is any stream that cannot seek: making armor
  seekable would mean decoding the whole file into memory.

### Header inspection

Read the header of an encrypted file without decrypting it. Nothing in it is authenticated: that
takes the file key, so an identity.

```csharp
var header = AgeHeader.Read(stream);    // or await AgeHeader.ReadAsync(stream)

Console.WriteLine($"Stanzas: {header.Stanzas.Count}");
Console.WriteLine($"Armored: {header.IsArmored}");
Console.WriteLine($"Payload offset: {header.PayloadOffset}");   // null for an armored file

foreach (var stanza in header.Stanzas)
    Console.WriteLine($"  {stanza.Type}: {stanza.Args[0]}");
```

### Armor on its own

Convert an encrypted file to ASCII armor and back, with no key: armor only re-encodes the
ciphertext.

```csharp
Armor.Encode(binaryFile, armoredFile);
Armor.Decode(armoredFile, binaryFile);    // held to the rules decryption applies
```

### Parse existing keys

```csharp
var recipient = Recipients.ParseOne(line);                     // any type
var tagged = P256TagRecipient.Parse("age1tag1...");            // a specific type

using var identity = Identities.ParseOne(secret);              // any type
using var keys = Identities.Parse(File.ReadAllText("keys.txt")); // an identity file
```

`Recipients.ParseOne` reads a recipient of any type: `age1…`, `age1pq1…`, `age1tag1…`,
`age1tagpq1…`, a plugin's `age1name1…`, or an SSH public key. `Identities.ParseOne` reads
`AGE-SECRET-KEY-1…`, `AGE-SECRET-KEY-PQ-1…`, a plugin's `AGE-PLUGIN-…`, or an SSH private
key that has no passphrase; `SshIdentity.Parse` reads one that has.

An `Identities` set parsed from a file owns its keys: disposing it clears them.
Identities you build a set from stay yours to dispose.

### Passphrase-protected identity files

An identity file encrypted to a passphrase, as `age -p` writes one, is an identity in its own
right. It asks for its passphrase only when a file is tried against it, and AgeSharp's own
identities are tried first, so of several such files only the one that opens the file asks:

```csharp
using var keys = new EncryptedIdentityFile(File.ReadAllBytes("keys.age"), () => PromptForPassphrase());
new Identities(keys).Decrypt(input, output);

IReadOnlyList<IRecipient> mine = keys.GetRecipients();   // for encrypting to your own keys
```

The characters the callback returns are cleared once used. To write such a file, encrypt the
identity file to a `Passphrase`:

```csharp
using var passphrase = new Passphrase(characters);
var protectedKeys = new Recipients(passphrase).Encrypt(Encoding.UTF8.GetBytes(identityFileText));
```

### File keys

Each file's payload is sealed under a file key the header wraps for every recipient. The header
can be unwrapped in one place and the payload decrypted in another, without the ciphertext
or the identity changing hands, as go-age's `ExtractHeader`, `DecryptHeader` and
`NewInjectedFileKeyIdentity` allow:

```csharp
// Where the identity is: from the header alone, the file key
var header = AgeHeader.Read(file);             // header.ToBytes() is the detached header
using var fileKey = new Identities(identity).UnwrapFileKey(header);
byte[] carried = fileKey.Bytes.ToArray();

// Where the ciphertext is: decrypt with the key
using var known = new FileKeyIdentity(FileKey.From(carried));
new Identities(known).Decrypt(ciphertext, plaintext);
```

This is low-level: whoever holds a file key can read that one file, so keeping track of which
file a key belongs to, and using it for nothing else, is yours to do. The header's MAC is still
checked, so a key that isn't the file's fails as an `AgeAuthenticationException`. `FileKey` and
`FileKeyIdentity` clear their copy of the key when disposed.

### Plugins

Recipients and identities of a plugin's type (`age1yubikey1…`, `AGE-PLUGIN-YUBIKEY-1…`) run the
matching `age-plugin-*` binary from `PATH`. A plugin talks to the user through
`IPluginCallbacks`, which is told which plugin asks:

```csharp
class Prompts : IPluginCallbacks
{
    public void DisplayMessage(string plugin, string message) => Console.WriteLine($"{plugin}: {message}");
    public string? RequestValue(string plugin, string prompt) => Console.ReadLine();   // null declines
    public char[]? RequestSecret(string plugin, string prompt) => ReadPin(prompt);   // cleared once sent
    public bool Confirm(string plugin, string message, string yes, string? no) => Ask(message, yes, no);
    public void Waiting(string plugin) => Console.WriteLine($"{plugin}: touch your key");
}

using var keys = Identities.Parse(File.ReadAllText("keys.txt"), new Prompts());
```

Without callbacks, every request is answered as a failure, as the plugin protocol says for a
client with no user interface; so is a callback that throws. `Waiting` is called once a plugin
has kept the operation waiting five seconds, usually for a touch. A plugin's security labels
(`postquantum`, say) are passed on, so its stanzas mix only with recipients that declare the same.

### Writing a plugin

`AgePlugin` is the other side of the protocol, for an `age-plugin-<name>` binary written in
.NET, as go-age's `plugin` package is for Go. A plugin exposes ordinary `IRecipient`s and
`IIdentity`s: it says how to make them from the data in its keys, and `Run` speaks the protocol
around them for any client (age, rage, AgeSharp):

```csharp
var plugin = new AgePlugin("frood");   // age-plugin-frood, age1frood1…, AGE-PLUGIN-FROOD-1…

plugin.HandleRecipient(data => new FroodRecipient(plugin, data));
plugin.HandleIdentity(data => new FroodIdentity(plugin, data));
plugin.HandleIdentityAsRecipient(data => new FroodIdentity(plugin, data).Recipient);   // optional

if (args is ["keygen"])
{
    var key = NewFroodKey();
    Console.WriteLine(plugin.EncodeIdentity(key.Secret));
    Console.WriteLine(plugin.EncodeRecipient(key.Public));
    return 0;
}

return plugin.Run(args);   // --age-plugin=recipient-v1 or identity-v1, from the client
```

From inside `Wrap` or `TryUnwrap`, a recipient or identity talks to the user through the client
with `plugin.DisplayMessage`, `RequestValue`, `RequestSecret` and `Confirm`. An exception thrown
there, or by a handler, is reported to the client as that key's error; an identity that returns
false is not the one for the file. A recipient's labels (`IRecipientWithLabels`) are passed on.
The exit codes are go-age's.

### Custom recipients and identities

Implement `IRecipient` and `IIdentity` to integrate custom key types,
remote secrets managers, or age plugins.

```csharp
public class MyRecipient : IRecipient
{
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Wrap the file key using your custom scheme. One recipient may
        // produce several stanzas; most produce one.
        return [new Stanza("MyType", ["arg1"], wrappedKey)];
    }
}

public class MyIdentity : IIdentity
{
    public bool TryUnwrap(Stanza stanza, Span<byte> fileKey)
    {
        // Called for each stanza in the file's header. If the stanza is
        // yours, write the 16-byte file key into fileKey and return true;
        // otherwise return false.
    }
}
```

A recipient whose files must not be mixed with others (as post-quantum ones must
not be mixed with classical ones) implements `IRecipientWithLabels` and returns
its labels with its stanzas; every recipient of a file must carry the same set.
An identity that knows its recipient implements `IIdentityWithRecipient`.

When decrypting, AgeSharp's own identities (X25519, ML-KEM-768-X25519, scrypt) are
tried before any other, whatever order they are passed in, as in the Go
implementation. A custom, SSH or plugin identity, which may ask the user for a
passphrase or a touch, is asked only if none of those opens the file.

### Errors

Everything this library throws while reading or writing a file is an `AgeException`:

| Type | Means |
| --- | --- |
| `AgeFormatException` | The file does not parse: a malformed header, stanza or armor, or a parsing limit exceeded |
| `AgeAuthenticationException` | A cryptographic check failed: the header MAC, a payload chunk, or a truncated or extended file. Tampered with or damaged |
| `NoIdentityMatchException` | None of the identities opened any of the file's stanzas |
| `AgePluginException` | A plugin failed to start, misbehaved, or reported an error |
| `AgeException` itself | A caller's mistake found only mid-way, such as recipients with different security labels |

Parsing a key, recipient or identity from text throws `FormatException`, as .NET's own
`Parse` methods do.

When no identity opens a file, `NoIdentityMatchException` says what the file holds
(`StanzaTypes`) and why each identity, in the order tried, did not open it (`Mismatches`).
AgeSharp's own identities tell "the file has no stanza of my type" from "it has some, none for
me"; a custom or plugin identity just did not match. It holds only text, never the identities:

```
no identity matched any recipient stanza; the file has X25519; X25519Identity
(age1q7f3k2m9x0vwlc…p4ft2hzq): the file's X25519 stanzas are not for it;
MlKem768X25519Identity (age1pq1zq5n8tlcd…8w6sk9ve): the file has no mlkem768x25519 stanza
```

### Parsing limits

An age header must be buffered in full before its MAC can be verified, so
AgeSharp caps how much it will read before authentication — otherwise a hostile
or truncated stream with an unterminated (or endlessly repeated) line could
exhaust memory. The limits are options of `AgeDecryptOptions`:

| Option | Default | Bounds |
| --- | --- | --- |
| `MaxHeaderBytes` | 2 MiB | The whole header (all stanzas) |
| `MaxRecipientStanzas` | 1024 | Recipient stanzas in a header |
| `MaxStanzaArguments` | 128 | Arguments on one stanza line |
| `MaxArmorLineBytes` | 1 KiB | A single ASCII-armor line |

```csharp
with.Decrypt(input, output, new AgeDecryptOptions { MaxRecipientStanzas = 4096 });
```

Exceeding a limit throws `AgeFormatException`. The age
[specification](https://github.com/C2SP/C2SP/blob/main/age.md) sets no such
bounds. The three header limits are the ones the Go implementation applies from
v1.3.2 on, so both accept and reject the same files; the armor line limit is
AgeSharp's own. They sit far above any real file (the largest built-in stanza
line is ~1.5 KiB, so 2 MiB holds well over a thousand post-quantum recipients),
so legitimate input never trips them; raise one only for legitimate input that does. A
header line is bounded only by `MaxHeaderBytes`, as in go-age. `RequireArmor` refuses
input that is not armored.

## Command line

AgeSharp is a library. For a command-line tool, use the reference
[age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage);
AgeSharp reads and writes the same files.

## Development

```sh
make build      # Build
make test       # Run all tests (interop tests run when age and rage are on PATH)
make bench      # Run BenchmarkDotNet benchmarks
```

## Benchmarks

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for BenchmarkDotNet results.

## Feature comparison

See [docs/FEATURE_COMPARISON.md](docs/FEATURE_COMPARISON.md) for a detailed comparison
with the Go reference implementation and Rust's `rage`.

## See also

- [age-encryption.org/v1](https://age-encryption.org/v1) — the age format specification
- [age](https://github.com/FiloSottile/age) — the reference Go implementation and CLI
- [rage](https://github.com/str4d/rage) — a Rust implementation of age
- [awesome-age](https://github.com/FiloSottile/awesome-age) — age plugins, tools, and integrations

AgeSharp targets .NET 10. If you need an older runtime, there is a community port
to .NET Standard 2.0 / .NET Framework 4.8:

- [AgeSharpNetStandard](https://github.com/davidmatson/AgeSharpNetStandard) — third-party,
  **not maintained or audited by this project**. It is a point-in-time port that may lag
  behind AgeSharp (including security fixes), so review it yourself before relying on it.
