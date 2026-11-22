# Feature comparison: AgeSharp vs Go (age) vs Rust (rage)

Compared on 2026-11-21: AgeSharp `main`, after the API rebuild, [age](https://github.com/FiloSottile/age) v1.3.2
and [rage](https://github.com/str4d/rage) 0.12.1, read from their source. The published
AgeSharp package may lag `main`; check the release notes for what a given version carries.

## Recipient and identity types

| Feature | Go (age) | Rust (rage) | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| X25519 | ✅ | ✅ | ✅ | |
| Scrypt/passphrase | ✅ | ✅ | ✅ | |
| SSH-Ed25519 | ✅ | ✅ | ✅ | |
| SSH-RSA | ✅ | ✅ | ✅ | |
| Passphrase-protected SSH keys | ✅ | ✅ | ✅ | Go reads OpenSSH keys protected with aes256-ctr or aes256-cbc, and legacy encrypted PEM (with the `.pub` file). rage reads more ciphers, refuses legacy PEM, and has no bcrypt round limit. AgeSharp reads OpenSSH keys with AES-CTR, AES-CBC, AES-GCM, ChaCha20-Poly1305 or 3DES, and like Go refuses more than 2048 bcrypt rounds. Like Go it reads legacy encrypted PEM ssh-rsa keys given the `.pub` file, with AES-CBC or 3DES but not single DES, which Go also reads |
| ML-KEM-768-X25519 (`age1pq1…`) | ✅ | ❌ | ✅ | In rage this is an open draft PR |
| Tagged P-256 (`age1tag1…`) | ✅ | ✅ | ✅ | Encryption only in all three; decryption is a plugin's job |
| Tagged P-256 + ML-KEM-768 (`age1tagpq1…`) | ✅ | ✅ | ✅ | As above |
| Plugin recipients and identities | ✅ | ✅ | ✅ | Client side of the `age-plugin-*` protocol |
| Writing plugins | ✅ | ✅ | ✅ | Go's `plugin` package, rage's `age-plugin` crate, AgeSharp's `AgePlugin` (modelled on Go's) |

AgeSharp's P-256 exchange for both runs on the platform's constant-time ECDH; in the browser,
which has none, it falls back to BouncyCastle's, which is not constant-time. The rest of the HPKE
is BouncyCastle's and AgeSharp's own, so both also work in the browser.

## Core format

| Feature | Go | Rust | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| Multi-recipient encryption | ✅ | ✅ | ✅ | |
| ASCII armor | ✅ | ✅ | ✅ | |
| Streaming, bounded memory | ✅ | ✅ | ✅ | 64 KiB chunks |
| Security labels (prevent mixing) | ✅ | ✅ | ✅ | A set of labels per recipient, compared unordered, as in Go |
| Encrypted identity files | ✅ | ✅ | ✅ | Decrypted only when first needed, as Go's `EncryptedIdentity` is (`EncryptedIdentityFile`) |
| Recipients files | ✅ | ✅ | ✅ | |
| Header limits (2 MiB, 1024 stanzas, 128 arguments) | ✅ | ❌ | ✅ | Introduced by Go v1.3.2; not in the spec. Adjustable in AgeSharp through `AgeDecryptOptions`, with go-age's values as defaults |
| Armor line length bound | ❌ | ❌ | ✅ | 1 KiB |
| C2SP conformance vectors | ✅ | ✅ | ✅ | AgeSharp passes all 147 of the 2026-08-29 set |

## Library APIs

| Feature | Go | Rust | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| Pull-based streams (`EncryptReader`) | ✅ | ✅ | ✅ | |
| Push-based streams (writers) | ✅ | ✅ | ✅ | Go's `Encrypt` and rage's `wrap_output` push encryption only; AgeSharp pushes decryption too (`DecryptWriter`) |
| Random-access decryption | ✅ | ✅ | ✅ | Go `DecryptReaderAt`, rage `Seek` on its stream reader, AgeSharp a seekable `DecryptReader` result; binary files only in AgeSharp |
| Detached headers | ✅ | ❌ | ✅ | |
| File-key extraction and injection | ✅ | ❌ | ✅ | Go `ExtractHeader`, `DecryptHeader`, `NewInjectedFileKeyIdentity`; AgeSharp `AgeHeader.ToBytes`, `Identities.UnwrapFileKey`, `FileKeyIdentity` |
| Header inspection | — | ❌ | ✅ | go-age's inspection is internal to its `age-inspect` command; its library exposes the raw header through `ExtractHeader` |
| Standalone armor reader/writer | ✅ | ✅ | ✅ | `Armor.Encode` / `Armor.Decode`, sync and async |
| Adjustable scrypt maximum work factor | ✅ | ✅ | ✅ | `Passphrase.MaxWorkFactor`, default 22 as in Go |
| Per-identity errors on no match | ✅ | ❌ | ✅ | Go collects each identity's error; AgeSharp says, for its own identities, whether the file had no stanza of their type or none for them |
| Async encrypt/decrypt | ❌ | ✅ | ✅ | `EncryptAsync`, `DecryptAsync`, `DecryptReaderAsync` and the detached forms, async all the way through; wrapping and unwrapping themselves are synchronous (`IRecipient.Wrap`, `IIdentity.TryUnwrap`), so a plugin or a passphrase prompt blocks |
| Browser / WebAssembly | — | ✅ | ✅ | rage's `age` crate builds for `wasm32-unknown-unknown`; AgeSharp runs under Blazor WebAssembly with a managed ChaCha20-Poly1305 backend, but of protected SSH keys only ed25519 with AES-GCM or ChaCha20-Poly1305. Not a stated target for Go |

## Command line

AgeSharp is a library only. go-age ships `age`, `age-keygen` and `age-inspect`, and rage
ships `rage`, `rage-keygen` and `rage-mount`; use those for the command line.

## Summary

AgeSharp covers the five standard recipient types and the two tagged ones (encryption only), both sides of the plugin protocol, and Go's
v1.3 library additions: detached headers, pull-based streams, random-access decryption and
file-key extraction and injection; it also inspects headers, which Go does only in its CLI. Like rage's library it runs in the browser, and it has the native ML-KEM-768-X25519
recipient (`age1pq1…`), which rage does not.

Where it still falls short: wrapping and unwrapping are synchronous, so a plugin or a passphrase
prompt blocks even under the async API; and in the browser only some protected SSH keys decrypt,
and the P-256 exchange is not constant-time.
