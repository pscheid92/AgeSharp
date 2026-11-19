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
- **Plugin protocol** — interoperates with `age-plugin-*` binaries
- Encrypt to multiple recipients
- ASCII armor support
- Streaming encryption and decryption across all APIs — memory is bounded
  by a single 64 KiB chunk buffer regardless of input size (1 GiB file uses
  the same working set as a 1 MB file)
- Pull-based streaming (`EncryptReader` / `DecryptReader`) returns a readable
  `Stream` for pipe-and-forget use cases
- Detached header APIs (`EncryptDetached` / `DecryptDetached`)
- Random-access decryption (`AgeRandomAccess`) — seek into encrypted files
- Header inspection without decryption (`AgeHeader.Parse`)
- Encrypted identity files (passphrase-protected)
- Recipients file parsing (`-R` style files with comments)
- Fully interoperable — files produced by AgeSharp decrypt with `age`, `rage`, and vice versa
- **Runs in Blazor WebAssembly** — automatically uses a managed
  ChaCha20-Poly1305 backend in the browser, where the platform cipher is
  unavailable. One exception: of passphrase-protected SSH keys, only ssh-ed25519
  keys protected with `aes256-gcm@openssh.com` or `chacha20-poly1305@openssh.com`
  decrypt there — not `ssh-keygen`'s default AES-CTR, and no ssh-rsa key

## Installation

```sh
dotnet add package AgeSharp
```

## Usage

### Encrypt and decrypt

```csharp
using Age;
using Age.Recipients;

using var identity = X25519Identity.Generate();
var recipient = identity.Recipient;

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
AgeEncrypt.Encrypt(input, encrypted, recipient);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
AgeEncrypt.Decrypt(encrypted, decrypted, identity);
```

### Passphrase encryption

```csharp
var passphrase = new ScryptRecipient("correct-horse-battery-staple");

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
AgeEncrypt.Encrypt(input, encrypted, passphrase);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
AgeEncrypt.Decrypt(encrypted, decrypted, passphrase);
```

### ASCII armor

```csharp
AgeEncrypt.Encrypt(input, encrypted, armor: true, recipient);

// -----BEGIN AGE ENCRYPTED FILE-----
// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA...
// -----END AGE ENCRYPTED FILE-----
```

### Multiple recipients

```csharp
using var alice = X25519Identity.Generate();
using var bob = X25519Identity.Generate();

AgeEncrypt.Encrypt(input, encrypted, alice.Recipient, bob.Recipient);

// Either identity can decrypt
AgeEncrypt.Decrypt(encrypted, decrypted, bob);
```

### SSH keys

```csharp
var recipient = SshEd25519Recipient.Parse("ssh-ed25519 AAAA...");
var identity = SshEd25519Identity.Parse(File.ReadAllText("/path/to/id_ed25519"));

AgeEncrypt.Encrypt(input, encrypted, recipient);

encrypted.Position = 0;
AgeEncrypt.Decrypt(encrypted, decrypted, identity);
```

A passphrase-protected key (OpenSSH format) needs somewhere to get its passphrase
from. It is asked for only when a file addressed to the key is decrypted, and
never for encrypting to the key:

```csharp
var identity = AgeKeygen.ParseSshIdentity(
    File.ReadAllText("/path/to/id_ed25519"),
    passphrase: () => PromptForPassphrase());
```

An ssh-rsa key protected in the older PEM format (`BEGIN RSA PRIVATE KEY` with
`Proc-Type: 4,ENCRYPTED`, as `ssh-keygen` wrote before OpenSSH 7.8 and still writes with
`-m PEM`) does not store its public key, so, as with `age`, it needs its `.pub` file
too. The decrypted key must match it:

```csharp
var identity = AgeKeygen.ParseSshIdentity(
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

AgeEncrypt.Encrypt(input, encrypted, recipient);
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
AgeEncrypt.Encrypt(input, encrypted, recipient);

// Recipients files read them too
var recipients = AgeKeygen.ParseRecipientsFile(File.ReadAllText("recipients.txt"));
```

### Pull-based streaming

Returns a readable `Stream` — header and key setup is eager, payload encryption/decryption is lazy (chunk-by-chunk on `Read()`).

```csharp
// Encrypt: returns a Stream you read ciphertext from
using var encryptedStream = AgeEncrypt.EncryptReader(plaintext, recipient);
encryptedStream.CopyTo(networkStream);

// Decrypt: returns a Stream you read plaintext from
using var decryptedStream = AgeEncrypt.DecryptReader(ciphertext, identity);
decryptedStream.CopyTo(outputStream);
```

### Detached headers

Splits the age header and payload into separate streams — useful for storing
the header and payload in different locations.

```csharp
// Encrypt with separate header and payload
AgeEncrypt.EncryptDetached(input, headerOutput, payloadOutput, recipient);

// Decrypt from separate streams
AgeEncrypt.DecryptDetached(headerInput, payloadInput, output, identity);
```

### Random-access decryption

Seek into an encrypted file and decrypt individual chunks without reading
the whole file — useful for encrypted archives, databases, and large files.

```csharp
using var ra = new AgeRandomAccess(ciphertext, identity);

Console.WriteLine($"Plaintext length: {ra.PlaintextLength}");

// Read 100 bytes at offset 50000
var buf = new byte[100];
ra.ReadAt(50000, buf);

// Or get a seekable Stream
using var stream = ra.GetStream();
stream.Seek(50000, SeekOrigin.Begin);
stream.Read(buf);
```

### Header inspection

Parse the header of an encrypted file without decrypting it.

```csharp
var header = AgeHeader.Parse(stream);

Console.WriteLine($"Recipients: {header.RecipientCount}");
Console.WriteLine($"Armored: {header.IsArmored}");
Console.WriteLine($"Payload offset: {header.PayloadOffset}");

foreach (var stanza in header.Recipients)
    Console.WriteLine($"  {stanza.Type}: {stanza.Args[0]}");
```

### Parse existing keys

```csharp
using var identity = AgeKeygen.ParseIdentity("AGE-SECRET-KEY-1...");
var recipient = AgeKeygen.ParseRecipient("age1...");
```

### Custom recipients and identities

Implement `IRecipient` and `IIdentity` to integrate custom key types,
remote secrets managers, or age plugins.

```csharp
public class MyRecipient : IRecipient
{
    public string? Label => null; // or a security label to prevent mixing

    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Wrap the file key using your custom scheme
        return new Stanza("MyType", ["arg1"], wrappedKey);
    }
}

public class MyIdentity : IIdentity
{
    public byte[]? Unwrap(Stanza stanza)
    {
        // Called once per stanza in the file's header. Return the file
        // key if this identity matches the stanza, null if not.
    }
}
```

When decrypting, AgeSharp's own identities (X25519, ML-KEM-768-X25519, scrypt) are
tried before any other, whatever order they are passed in, as in the Go
implementation. A custom, SSH or plugin identity, which may ask the user for a
passphrase or a touch, is asked only if none of those opens the file.

### Parsing limits

An age header must be buffered in full before its MAC can be verified, so
AgeSharp caps how much it will read before authentication — otherwise a hostile
or truncated stream with an unterminated (or endlessly repeated) line could
exhaust memory. The limits are exposed as constants on `AgeLimits`:

| Constant | Default | Bounds |
| --- | --- | --- |
| `AgeLimits.MaxHeaderBytes` | 2 MiB | The whole header (all stanzas) |
| `AgeLimits.MaxRecipientStanzas` | 1024 | Recipient stanzas in a header |
| `AgeLimits.MaxStanzaArguments` | 128 | Arguments on one stanza line |
| `AgeLimits.MaxArmorLineBytes` | 64 KiB | A single ASCII-armor line |

Exceeding a limit throws `AgeHeaderException` / `AgeArmorException`. The age
[specification](https://github.com/C2SP/C2SP/blob/main/age.md) sets no such
bounds. The three header limits are the ones the Go implementation applies from
v1.3.2 on, so both accept and reject the same files; the armor line limit is
AgeSharp's own. They sit far above any real file (the largest built-in stanza
line is ~1.5 KiB, so 2 MiB holds well over a thousand post-quantum recipients),
so legitimate input never trips them. `AgeLimits.MaxHeaderLineBytes` is obsolete:
a header line is bounded only by `MaxHeaderBytes`.

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
