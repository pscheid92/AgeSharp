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
  the same working set as a 1 MB file), on the synchronous and asynchronous
  paths alike, and for ASCII-armored input as well as binary
- Push- and pull-based streaming (`EncryptWriter` / `EncryptReader` / `DecryptReader`)
  return a readable or writable `Stream` for pipe-and-forget use cases
- Detached header APIs (`EncryptDetached` / `DecryptDetached`)
- Seekable decryption — `Age.DecryptReader` over a seekable source seeks into
  encrypted files without reading the whole file
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

> **Recipients vs. identities.** A **recipient** (`IRecipient`) is a public key
> you encrypt *to*; an **identity** (`IIdentity`) is the secret key you decrypt
> *with*. `X25519Identity.Generate()` gives you an identity, and
> `identity.Recipient` is its public half. A `Passphrase` is both at once. Every
> `Encrypt` overload takes recipients; every `Decrypt` overload takes identities.

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

For small payloads — secrets, database fields — there are buffer-in, buffer-out
overloads that skip the `MemoryStream` ceremony (`Encrypt` zeroes its plaintext copy):

```csharp
byte[] ciphertext = Age.Encrypt("secret"u8, recipient);
byte[] plaintext  = Age.Decrypt(ciphertext, identity);
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
Age.Encrypt(input, encrypted, new AgeEncryptOptions { Armor = true }, recipient);

// -----BEGIN AGE ENCRYPTED FILE-----
// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA...
// -----END AGE ENCRYPTED FILE-----
```

Decryption auto-detects armor on any stream, so you never have to say which form
you have. `AgeDecryptOptions.RequireArmor` is a *strictness* opt-in, for when
silently accepting the wrong form would be a bug:

```csharp
Age.Decrypt(input, output, identity);                                                // either form
Age.Decrypt(input, output, new AgeDecryptOptions { RequireArmor = true }, identity);  // armored only
```

### Multiple recipients

```csharp
using var alice = X25519Identity.Generate();
using var bob = X25519Identity.Generate();

Age.Encrypt(input, encrypted, alice.Recipient, bob.Recipient);

// Either identity can decrypt
Age.Decrypt(encrypted, decrypted, bob);
```

Recipients assembled at runtime go through the same call as a collection — no
splatting needed:

```csharp
List<IRecipient> recipients = LoadRecipientsFile(path);

Age.Encrypt(input, encrypted, recipients);
Age.Encrypt(input, encrypted, new AgeEncryptOptions { Armor = true }, recipients);
```

Every entry point takes both shapes: one-or-more positional arguments, or any
`IReadOnlyList<>`. The first recipient (or identity) is a required parameter
rather than part of the `params` tail, so forgetting them entirely is a compile
error instead of an exception at run time.

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

### Push-based streaming

`Age.EncryptWriter` returns a writable `Stream` (GZipStream-style): write plaintext to
it, and ciphertext is written to the destination. Recipient wrapping runs eagerly;
the header write is deferred to the first write; disposing finalizes the age file.

```csharp
// Write plaintext in; ciphertext flows to destination as you write.
using (var stream = Age.EncryptWriter(destination, recipient))
    inputStream.CopyTo(stream);   // Dispose finalizes the file (empty input → valid empty file)
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

> **Stream ownership.** The streaming APIs never dispose the streams you pass in —
> you own the destination/source and dispose it yourself. Disposing the stream
> returned by `EncryptWriter`/`DecryptReader`/`EncryptReader` releases only that wrapper
> (and, for `EncryptWriter`, finalizes the age file); the underlying stream stays open.
>
> **Thread-safety.** Recipients and identities are safe for concurrent use across
> threads. The returned streams are not — like any `Stream`, use one per thread.

### Async

`EncryptAsync`, `DecryptAsync`, and `DecryptReaderAsync` run with no blocking I/O on
either stream — safe under ASP.NET Core's `AllowSynchronousIO = false`. The
returned decrypt streams (and the push/pull streams above) implement
`ReadAsync`/`WriteAsync`/`DisposeAsync`, and a `CancellationToken` is threaded
through every operation. Async methods take `IReadOnlyList<>` rather than a
`params` span (spans can't cross an `await`).

```csharp
await Age.EncryptAsync(input, output, [recipient], new AgeEncryptOptions { Armor = true }, cancellationToken);
await Age.DecryptAsync(ciphertext, output, [identity], cancellationToken: cancellationToken);

await using var stream = await Age.DecryptReaderAsync(source, [identity], cancellationToken: cancellationToken);
await stream.CopyToAsync(outputStream, cancellationToken);
```

The async methods are not simple overloads of their synchronous counterparts — they
differ in shape, though no longer in capability:

| | sync | async |
| --- | --- | --- |
| Recipients / identities | `params ReadOnlySpan<>` | `IReadOnlyList<>` (spans can't cross an `await`) |
| Options | `AgeEncryptOptions` / `AgeDecryptOptions`, positional before the params span | same types, optional after the collection — so a `CancellationToken` needs a named argument |
| Seekability | `CanSeek` mirrors the source | same |
| `byte[]` overloads | yes | no equivalent |
| Detached header | yes | no equivalent |

One limitation: a plugin recipient/identity still performs **synchronous**
child-process I/O while wrapping or unwrapping, even on the async paths — the plugin
interfaces are synchronous, matching the reference implementation.

### Detached headers

Splits the age header and payload into separate streams — useful for storing
the header and payload in different locations.

```csharp
// Encrypt with separate header and payload
Age.EncryptDetached(input, headerOutput, payloadOutput, recipient);

// Decrypt from separate streams
Age.DecryptDetached(headerInput, payloadInput, output, identity);
```

### Seekable decryption

When the ciphertext source is seekable, `Age.DecryptReader` returns a seekable
plaintext `Stream`: `Length` is the plaintext length, `Seek` maps to the
containing 64 KiB chunk, and the last-read chunk is cached. This decrypts
individual regions without reading the whole file — useful for encrypted
archives, databases, and large files. `Age.DecryptReaderAsync` does the same. (A
non-seekable source yields a forward-only stream, as does an armored one —
ASCII armor is decoded a line at a time, which gives up seeking rather than
buying it with the file's size in memory.)

Opening a seekable source decrypts the final chunk to authenticate the plaintext
length, so a truncated file is rejected before the first read rather than
reporting a plausible wrong `Length`.

```csharp
using var stream = Age.DecryptReader(ciphertext, identity);

Console.WriteLine($"Plaintext length: {stream.Length}");

// Read 100 bytes at offset 50000
var buf = new byte[100];
stream.Seek(50000, SeekOrigin.Begin);
stream.ReadExactly(buf);
```

> Truncation of the payload is only detected once a read reaches the affected
> chunk, so a seek-and-read that never touches the final chunk cannot observe a
> truncated tail.

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
exhaust memory. The limits are per-call properties on `AgeDecryptOptions`, passed to
any decrypt or header-inspection method:

| `AgeDecryptOptions` property | Default | Bounds |
| --- | --- | --- |
| `MaxHeaderLineBytes` | 64 KiB | A single header line |
| `MaxHeaderBytes` | 16 MiB | The whole header (all stanzas) |
| `MaxArmorLineBytes` | 64 KiB | A single ASCII-armor line |

```csharp
var options = new AgeDecryptOptions { MaxHeaderBytes = 1024 * 1024 };
Age.Decrypt(input, output, options, identity);
```

> **Two options types.** `AgeEncryptOptions` carries what encryption can configure
> (`Armor`); `AgeDecryptOptions` carries what parsing can (`RequireArmor` and the three
> limits above). They are separate so that no member is inert where it is accepted —
> and because "produce armor" and "require armor" are different enough to deserve
> different names rather than one flag that changes meaning by direction.
>
> **Where options go.** Every synchronous method that takes options does so the same
> way — a second overload with `options` positional, immediately before the `params`
> recipients or identities. The async methods take it as a trailing optional argument
> instead, because `params` and optional arguments cannot coexist; that is the one
> difference, and it is why a `CancellationToken` needs a named argument there.
> `EncryptDetached` is the sole entry point with no options overload: armor wraps a
> whole age file, which a detached header and payload are not, so there is nothing
> for `AgeEncryptOptions` to configure.

Exceeding a limit throws `AgeFormatException`. The age
[specification](https://github.com/C2SP/C2SP/blob/main/age.md) sets no such
bounds, so these are AgeSharp's own defense; they sit far above any real file
(the largest built-in stanza line is ~1.5 KiB, and 16 MiB still allows well over
100,000 recipients), so legitimate input never trips them.

## Errors

Every error thrown by AgeSharp derives from `AgeException`, split by one rule: if
the input's *structure* can't be parsed it's an `AgeFormatException`; if the
structure parsed but a *cryptographic check* failed it's an
`AgeAuthenticationException`.

| Exception | Thrown when |
| --- | --- |
| `AgeException` | base type — catch this to handle any AgeSharp error |
| `AgeFormatException` | malformed header, stanza, or ASCII armor; a parsing limit exceeded; a bad key/recipient/identity string |
| `AgeAuthenticationException` | the header MAC failed, a payload chunk failed authentication, or the STREAM was truncated/extended/reordered |
| `NoIdentityMatchException` | none of the supplied identities matched any recipient stanza |
| `AgePluginException` | an `age-plugin-*` binary failed to start or misbehaved |

`Parse` methods throw `AgeFormatException` on bad input; the `TryParse` variants
never throw. Empty recipients/identities on any entry point throw
`ArgumentException`.

```csharp
try
{
    Age.Decrypt(input, output, identity);
}
catch (NoIdentityMatchException)      { /* wrong key */ }
catch (AgeAuthenticationException)    { /* tampered or corrupted */ }
catch (AgeFormatException)            { /* not a well-formed age file */ }
```

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
