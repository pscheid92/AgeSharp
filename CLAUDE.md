# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

AgeSharp is a .NET 10 implementation of the [age encryption format](https://age-encryption.org/v1).
The format spec is vendored at `docs/spec/age.md` and `docs/spec/age-plugin.md` — consult it before
changing anything about wire format, stanza handling, or key derivation.

## Commands

```sh
make test       # all tests
make build      # framework-dependent build
make            # universal macOS binary (AOT)
make interop    # interop tests against the Go age CLI
make bench      # BenchmarkDotNet
```

```sh
dotnet test --filter "FullyQualifiedName~DecryptWriterTests"   # one class
dotnet test --filter "FullyQualifiedName~EmptyPlaintext"       # one test
```

Two things CI does that a local `dotnet test` does not:

- `dotnet build -p:TreatWarningsAsErrors=true` — warnings fail the build in CI, so treat them as errors locally.
- `dotnet test -p:ForcePortableAead=true` — forces the managed ChaCha20-Poly1305 backend
  (`AeadCipher`, guarded by `FORCE_PORTABLE_AEAD`). The whole suite must pass on both backends;
  run it this way after touching anything under `Age/Crypto/`.

Interop tests self-skip when the `age` CLI is absent from PATH, so a green local run does not
mean they executed.

## Architecture

### The streaming grid

The public API is organised as four cells, and every decision about a stream lives in one of them:

|         | pull (caller reads) | push (caller writes) |
|---------|---------------------|----------------------|
| encrypt | `Age.EncryptReader` | `Age.EncryptWriter`  |
| decrypt | `Age.DecryptReader` | `Age.DecryptWriter`  |

Three of the four set up eagerly — recipients wrapped, key derived, header parsed — so caller errors
surface from the factory call. `DecryptWriter` cannot: nothing about the file is known until bytes
arrive, so "no identity matches" throws from a `Write`, and the final chunk is only recognisable as
final at `Dispose`. **Disposing a `DecryptWriter` is not optional** — a stream never disposed has
neither authenticated its last chunk nor detected truncation.

The one-shot `Encrypt`/`Decrypt` overloads and the `byte[]` overloads are thin wrappers over these.

### Sans-I/O cores

Header parsing and ASCII armor are byte-fed state machines that never touch a stream:
`HeaderLineAccumulator`, `ArmorLineAccumulator`, `ArmorDecoder`/`ArmorEncoder`, `HeaderReader`. This is why the
sync and async paths share all framing, validation, and decoding — only the fill differs. When
fixing a bug in either path, check whether the fix belongs in the shared core, and whether the
*other* path needs the same change. Sync/async divergence has been a recurring bug source here.

### Seekable vs forward-only dispatch

`DecryptReader` mirrors the source: a seekable input yields `SeekableDecryptStream` (random access,
O(1) chunk seeks), anything else yields forward-only `DecryptStream`. Two invariants matter:

- `SeekableDecryptStream.Create` **eagerly decrypts the final chunk** to authenticate the plaintext
  length. Chunk layout alone cannot distinguish a truncated file from a shorter one, so without this
  the same file would behave differently depending on whether the caller's stream happened to be
  seekable. Do not make this lazy.
- Armored input stays seekable via `ArmorGeometry`, which translates a binary offset to a text
  position in O(1) from the fixed line geometry. Its arithmetic is only valid while it agrees with
  what `ArmorDecoder` accepts and the writers emit — hence the shared `ArmorFormat` constants. A
  mismatch produces offsets that land mid-line, which surfaces as an authentication failure rather
  than anything legible.

### Recipients and identities

`IRecipient` wraps a file key into one or more `Stanza`s; `IIdentity` tries to unwrap one. Optional capabilities
are separate interfaces rather than members, so custom types implement only what they need:
`IRecipientWithLabels` (security labels — all recipients in a file must produce equal label sets)
and `IIdentityWithRecipient` (derive the public half). `IIdentity` extends `IDisposable` with a
default no-op so implementations holding no secrets need not write one.

Rules enforced on both encrypt and decrypt: an scrypt (`Passphrase`) stanza must be the only stanza
in a header, and label sets must match across recipients.

### Conventions with teeth

- **Stream ownership**: the library never disposes a caller's stream. Wrappers dispose only what
  they created. Violating this has shipped as a bug before.
- **Secret hygiene**: key material is zeroed with `CryptographicOperations.ZeroMemory`, in a
  `finally` so error paths clear it too. `Encrypt`/`Decrypt` byte[] overloads zero their intermediate
  buffers. Apply this to any new path handling a file key, payload key, or plaintext.
- **One X25519 agreement path**: all agreements go through `CryptoHelper.X25519Agree`, which rejects
  an all-zero shared secret. Do not hand-roll `X25519Agreement` at a call site.
- **Public API is tracked**: `Age/PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt` are enforced
  by `Microsoft.CodeAnalysis.PublicApiAnalyzers`. Adding public surface requires an Unshipped entry;
  removing shipped surface requires a `*REMOVED*` line. The build fails otherwise.
- **Namespaces are flat**: everything public is `AgeSharp`; `AgeSharp.Crypto` is internal-only. This
  is deliberate (`f41a214`) — do not introduce sub-namespaces for public types.
- **Overload shape**: one method per operation. Recipients and identities are always an
  `IReadOnlyList<T>` (a collection expression at the call site — `[recipient]`), and options are
  always the last parameter, optional and defaulting to null. The async members are the same shape
  plus a trailing `CancellationToken`. Do not add `params` or per-options overloads: the facade was
  deliberately collapsed from ~50 methods to this one rule, and `Materialize` in `Age.cs` is the
  single place recipients and identities are validated (null, empty, null elements).
  `RS0026` is suppressed in `Age.csproj` for this shape — see the comment there for why it is safe.

### Exceptions

`AgeException` is the catch-all base. `AgeFormatException` (malformed input),
`AgeAuthenticationException` (MAC or AEAD failure, including truncation), `NoIdentityMatchException`,
`AgePluginException`. Anything escaping the public API should derive from `AgeException` — a raw
BCL or BouncyCastle exception reaching a caller is a bug.

## Layout

`Age/` is the library: `Age.cs` plus `Age.Async.cs`, `Age.Parsing.cs`, and `Age.Header.cs` are the partial facade;
`Crypto/`, `Format/`, `Recipients/`, `Plugin/` hold the implementation. `Age.Cli/` is the CLI,
`Age.Tests/` the suite, `Age.TestKit/` runs the Community Cryptography Test Vectors from
`testdata/`, `Age.Benchmarks/` is BenchmarkDotNet.
