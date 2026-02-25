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
- Pull-based streaming (`EncryptReader` / `DecryptReader`)
- Detached header APIs (`EncryptDetached` / `DecryptDetached`)
- Random-access decryption (`AgeRandomAccess`) — seek into encrypted files
- Header inspection without decryption (`AgeHeader.Parse`)
- Encrypted identity files (passphrase-protected)
- Recipients file parsing (`-R` style files with comments)
- Fully interoperable — files produced by AgeSharp decrypt with `age`, `rage`, and vice versa

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
var identity = SshEd25519Identity.CreateFromFile("/path/to/id_ed25519");

AgeEncrypt.Encrypt(input, encrypted, recipient);

encrypted.Position = 0;
AgeEncrypt.Decrypt(encrypted, decrypted, identity);
```

### Post-quantum (ML-KEM-768-X25519)

```csharp
using var identity = MlKem768X25519Identity.Generate();
var recipient = identity.Recipient;

AgeEncrypt.Encrypt(input, encrypted, recipient);
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
    public byte[]? Unwrap(IReadOnlyList<Stanza> stanzas)
    {
        // Return the file key if matched, null if not
    }
}
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

## Feature comparison

See [FEATURE_COMPARISON.md](FEATURE_COMPARISON.md) for a detailed comparison
with the Go reference implementation and Rust's `rage`.

## See also

- [age-encryption.org/v1](https://age-encryption.org/v1) — the age format specification
- [age](https://github.com/FiloSottile/age) — the reference Go implementation and CLI
- [rage](https://github.com/str4d/rage) — a Rust implementation of age
- [awesome-age](https://github.com/FiloSottile/awesome-age) — age plugins, tools, and integrations
