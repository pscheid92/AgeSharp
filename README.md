<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, a wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

[![NuGet](https://img.shields.io/nuget/v/AgeSharp)](https://www.nuget.org/packages/AgeSharp)

[`AgeSharp`](https://github.com/pscheid/AgeSharp) is a C# implementation of the
[age](https://age-encryption.org) file encryption format, fully interoperable
with the reference [Go implementation](https://github.com/FiloSottile/age) and
other age-compatible tools.

It depends only on [NSec.Cryptography](https://nsec.rocks/) (which bundles
libsodium), and targets .NET 10.

### Features

- Simple, streaming API — encrypt and decrypt with a single method call
- X25519 key pairs and scrypt passphrase encryption
- ASCII armor (PEM) support
- Encrypt to multiple recipients
- Extensible via custom `IRecipient` / `IIdentity` implementations
- Interoperable — files produced by AgeSharp can be decrypted by `age`, `rage`, and vice versa
- Minimal dependencies — only NSec.Cryptography / libsodium

## Installation

```sh
dotnet add package AgeSharp
```

## Usage

`AgeSharp` provides a simple static API in the `Age` namespace.

#### Encrypt and decrypt with a new recipient / identity pair

```csharp
using Age;
using Age.Recipients;

using var identity = X25519Identity.Generate();
var recipient = identity.Recipient;
Console.WriteLine(identity);  // AGE-SECRET-KEY-1...
Console.WriteLine(recipient); // age1...

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
AgeEncrypt.Encrypt(input, encrypted, recipient);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
AgeEncrypt.Decrypt(encrypted, decrypted, identity);

Console.WriteLine(Encoding.UTF8.GetString(decrypted.ToArray()));
```

#### Encrypt and decrypt with a passphrase

```csharp
using Age;
using Age.Recipients;

var passphrase = new ScryptRecipient("burst-swarm-slender-curve-ability-various-crystal-moon-affair-three");

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
AgeEncrypt.Encrypt(input, encrypted, passphrase);

encrypted.Position = 0;
using var decrypted = new MemoryStream();
AgeEncrypt.Decrypt(encrypted, decrypted, passphrase);
```

#### ASCII armoring

age encrypted files are binary. There is an official ASCII "armor" format, based
on PEM, which provides a way to encode an encrypted file as text.

```csharp
using Age;
using Age.Recipients;

using var identity = X25519Identity.Generate();

using var input = new MemoryStream("Hello, age!"u8.ToArray());
using var encrypted = new MemoryStream();
AgeEncrypt.Encrypt(input, encrypted, armor: true, identity.Recipient);

// -----BEGIN AGE ENCRYPTED FILE-----
// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA...
// -----END AGE ENCRYPTED FILE-----
```

#### Encrypt to multiple recipients

```csharp
using Age;
using Age.Recipients;

using var alice = X25519Identity.Generate();
using var bob = X25519Identity.Generate();

using var input = new MemoryStream("Hello, everyone!"u8.ToArray());
using var encrypted = new MemoryStream();
AgeEncrypt.Encrypt(input, encrypted, alice.Recipient, bob.Recipient);

// Either identity can decrypt
encrypted.Position = 0;
using var decrypted = new MemoryStream();
AgeEncrypt.Decrypt(encrypted, decrypted, bob);
```

#### Parse existing keys

```csharp
using Age;

var identity = AgeKeygen.ParseIdentity("AGE-SECRET-KEY-1...");
var recipient = AgeKeygen.ParseRecipient("age1...");
```

### Custom recipients and identities

You can implement the `IRecipient` and `IIdentity` interfaces to use custom
types as recipients and identities.

```csharp
using Age.Format;
using Age.Recipients;

public class MyRecipient : IRecipient
{
    public Stanza Wrap(ReadOnlySpan<byte> fileKey)
    {
        // Wrap the file key using your custom scheme
    }
}

public class MyIdentity : IIdentity
{
    public byte[]? Unwrap(Stanza stanza)
    {
        // Return the file key if this identity matches, null if not
    }
}
```

This lets you integrate remote APIs, secrets managers, and interoperate with
[age plugins](https://github.com/FiloSottile/awesome-age?tab=readme-ov-file#plugins).

## See also

- [age-encryption.org/v1](https://age-encryption.org/v1) — the age format specification
- [age](https://github.com/FiloSottile/age) — the reference Go implementation and CLI
- [rage](https://github.com/str4d/rage) — a Rust implementation of age
- [awesome-age](https://github.com/FiloSottile/awesome-age) — a collection of age plugins, tools, and integrations
