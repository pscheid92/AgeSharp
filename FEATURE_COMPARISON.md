# Feature Completeness: AgeSharp vs Go (age) vs Rust (rage)

## Recipient/Identity Types

| Feature | Go (age) | Rust (rage) | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| X25519 | ✅ | ✅ | ✅ | |
| Scrypt/passphrase | ✅ | ✅ | ✅ | |
| SSH-Ed25519 | ✅ | ✅ | ✅ | |
| SSH-RSA | ✅ | ✅ | ✅ | |
| ML-KEM-768-X25519 (PQ) | ✅ | ❌ | ✅ | rage has no built-in PQ; AgeSharp is ahead of rage here |
| Plugin recipients | ✅ | ✅ | ❌ | stdin/stdout protocol for `age-plugin-*` binaries |

## Core Encryption Features

| Feature | Go | Rust | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| Multi-recipient encryption | ✅ | ✅ | ✅ | |
| ASCII armor | ✅ | ✅ | ✅ | |
| Streaming encryption | ✅ | ✅ | ✅ | STREAM cipher, 64KB chunks |
| Security labels (prevent mixing) | ✅ | ✅ | ✅ | PQ/scrypt label enforcement |
| Header MAC verification | ✅ | ✅ | ✅ | |
| Encrypted identity files | ✅ | ✅ | ✅ | Passphrase-protected age identity files |
| Recipients file parsing | ✅ | ✅ | ✅ | `-R` file with multiple recipients + comments |

## Advanced Features (Go v1.3.0+)

| Feature | Go | Rust | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| Random-access decryption (`DecryptReaderAt`) | ✅ | ❌ | ❌ | Seek into encrypted files (e.g. ZIP in age) |
| Detached header APIs | ✅ | ❌ | ❌ | Extract/decrypt header separately |
| `age-inspect` | ✅ | ❌ | ❌ | Metadata inspection without decryption |
| Pull-based encryption (`EncryptReader`) | ✅ | ✅ | ❌ | AgeSharp uses push-based only |
| Async I/O | ❌ | ✅ | ❌ | Rust-specific feature flag |

## CLI Tools

| Feature | Go | Rust | AgeSharp |
|---|:---:|:---:|:---:|
| `age`/`rage` encrypt/decrypt CLI | ✅ | ✅ | ❌ |
| `age-keygen`/`rage-keygen` | ✅ | ✅ | ❌ (API only) |
| `rage-mount` (FUSE) | ❌ | ✅ | ❌ |

## Summary

AgeSharp covers all the core encryption features — every recipient type from the base spec plus post-quantum. The main gaps vs the reference implementations:

1. **Plugin system** — The `age-plugin-*` protocol for extensible recipient types (both Go and Rust have this)
2. **CLI tool** — No command-line binary (library-only by design)
3. **Go v1.3.0 advanced APIs** — Random-access decryption, detached headers, `age-inspect` (only Go has these; rage doesn't either)

For a library targeting .NET developers, the plugin system is the only meaningful gap. The CLI and Go v1.3.0 advanced APIs are less critical since AgeSharp is a library, and even rage hasn't implemented those advanced Go features.
