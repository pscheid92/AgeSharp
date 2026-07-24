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

It depends only on [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography)
and targets .NET 10.

## Features

- All standard recipient types: X25519, scrypt/passphrase, SSH-Ed25519, SSH-RSA
- **Post-quantum** ML-KEM-768-X25519 hybrid encryption
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
- Header inspection without decryption (`Age.ReadHeader`)
- Encrypted identity files (passphrase-protected)
- Recipients file parsing (`-R` style files with comments)
- Fully interoperable — files produced by AgeSharp decrypt with `age`, `rage`, and vice versa
- **Runs in Blazor WebAssembly** — automatically uses a managed
  ChaCha20-Poly1305 backend in the browser, where the platform cipher is
  unavailable

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
Age.Encrypt(input, encrypted, recipient);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
Age.Decrypt(encrypted, decrypted, identity);
```

### Passphrase encryption

```csharp
var passphrase = new Passphrase("correct-horse-battery-staple");

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
Age.Encrypt(input, encrypted, passphrase);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
Age.Decrypt(encrypted, decrypted, passphrase);
```

### ASCII armor

```csharp
Age.Encrypt(input, encrypted, new AgeOptions { Armor = true }, recipient);

// -----BEGIN AGE ENCRYPTED FILE-----
// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA...
// -----END AGE ENCRYPTED FILE-----
```

### Multiple recipients

```csharp
using var alice = X25519Identity.Generate();
using var bob = X25519Identity.Generate();

Age.Encrypt(input, encrypted, alice.Recipient, bob.Recipient);

// Either identity can decrypt
Age.Decrypt(encrypted, decrypted, bob);
```

### SSH keys

```csharp
var recipient = SshEd25519Recipient.Parse("ssh-ed25519 AAAA...");
var identity = SshEd25519Identity.Parse(File.ReadAllText("/path/to/id_ed25519"));

Age.Encrypt(input, encrypted, recipient);

encrypted.Position = 0;
Age.Decrypt(encrypted, decrypted, identity);
```

### Post-quantum (ML-KEM-768-X25519)

```csharp
using var identity = MlKem768X25519Identity.Generate();
var recipient = identity.Recipient;

Age.Encrypt(input, encrypted, recipient);
```

### Pull-based streaming

Returns a readable `Stream` — header and key setup is eager, payload encryption/decryption is lazy (chunk-by-chunk on `Read()`).

```csharp
// Encrypt: returns a Stream you read ciphertext from
using var encryptedStream = Age.EncryptReader(plaintext, recipient);
encryptedStream.CopyTo(networkStream);

// Decrypt: returns a Stream you read plaintext from
using var decryptedStream = Age.DecryptReader(ciphertext, identity);
decryptedStream.CopyTo(outputStream);
```

### Detached headers

Splits the age header and payload into separate streams — useful for storing
the header and payload in different locations.

```csharp
// Encrypt with separate header and payload
Age.EncryptDetached(input, headerOutput, payloadOutput, recipient);

// Decrypt from separate streams
Age.DecryptDetached(headerInput, payloadInput, output, identity);
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
var header = Age.ReadHeader(stream);

Console.WriteLine($"Recipients: {header.Stanzas.Count}");
Console.WriteLine($"Armored: {header.IsArmored}");
Console.WriteLine($"Payload offset: {header.PayloadOffset}");

foreach (var stanza in header.Stanzas)
    Console.WriteLine($"  {stanza.Type}: {stanza.Args[0]}");
```

### Parse existing keys

`Age.ParseRecipient` / `Age.ParseIdentity` accept any supported format
(X25519, ML-KEM-768, plugin, or SSH) and dispatch on the string:

```csharp
IRecipient recipient = Age.ParseRecipient("age1...");
IIdentity identity = Age.ParseIdentity("AGE-SECRET-KEY-1...");

// Non-throwing variants:
if (Age.TryParseRecipient(userInput, out var r)) { /* ... */ }
```

Parse a specific type directly when you want the concrete type back (e.g. to
`Dispose` an identity that holds key material):

```csharp
using var x25519 = X25519Identity.Parse("AGE-SECRET-KEY-1...");
```

### Custom recipients and identities

Implement `IRecipient` and `IIdentity` to integrate custom key types,
remote secrets managers, or age plugins.

```csharp
public class MyRecipient : IRecipient
{
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Wrap the file key using your custom scheme
        return new Stanza("MyType", ["arg1"], wrappedKey);
    }
}

// To carry security labels (as the post-quantum recipient does, so it can't be
// mixed with classical recipients), also implement IRecipientWithLabels:
//     (Stanza, IReadOnlyCollection<string>) WrapWithLabels(ReadOnlySpan<byte> fileKey)

public class MyIdentity : IIdentity
{
    public byte[]? Unwrap(Stanza stanza)
    {
        // Called once per stanza in the file's header. Return the file
        // key if this identity matches the stanza, null if not.
    }
}
```

### Parsing limits

An age header must be buffered in full before its MAC can be verified, so
AgeSharp caps how much it will read before authentication — otherwise a hostile
or truncated stream with an unterminated (or endlessly repeated) line could
exhaust memory. The limits are per-call properties on `AgeOptions`, passed to
any decrypt or header-inspection method:

| `AgeOptions` property | Default | Bounds |
| --- | --- | --- |
| `MaxHeaderLineBytes` | 64 KiB | A single header line |
| `MaxHeaderBytes` | 16 MiB | The whole header (all stanzas) |
| `MaxArmorLineBytes` | 64 KiB | A single ASCII-armor line |

```csharp
var options = new AgeOptions { MaxHeaderBytes = 1024 * 1024 };
Age.Decrypt(input, output, options, identity);
```

Exceeding a limit throws `AgeFormatException`. The age
[specification](https://github.com/C2SP/C2SP/blob/main/age.md) sets no such
bounds, so these are AgeSharp's own defense; they sit far above any real file
(the largest built-in stanza line is ~1.5 KiB, and 16 MiB still allows well over
100,000 recipients), so legitimate input never trips them.

## CLI

`AgeSharp` ships a CLI compatible with the `age` command.

```sh
# Encrypt
age -r age1... -o encrypted.age plaintext.txt

# Decrypt
age -d -i key.txt -o plaintext.txt encrypted.age

# Generate a key pair
age-keygen -o key.txt

# Inspect an encrypted file (no decryption needed)
age inspect encrypted.age
```

## Development

```sh
make            # Build universal macOS binary (AOT)
make build      # Framework-dependent build
make test       # Run all tests
make bench      # Run BenchmarkDotNet benchmarks
make interop    # Interoperability tests vs Go age CLI
```

## Benchmarks

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for detailed benchmark results
comparing AgeSharp with the Go and Rust implementations.

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
