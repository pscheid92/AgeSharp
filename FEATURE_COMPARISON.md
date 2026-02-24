# Feature Completeness: AgeSharp vs Go (age) vs Rust (rage)

## Recipient/Identity Types

| Feature | Go (age) | Rust (rage) | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| X25519 | ✅ | ✅ | ✅ | |
| Scrypt/passphrase | ✅ | ✅ | ✅ | |
| SSH-Ed25519 | ✅ | ✅ | ✅ | |
| SSH-RSA | ✅ | ✅ | ✅ | |
| ML-KEM-768-X25519 (PQ) | ✅ | ❌ | ✅ | rage has no built-in PQ; AgeSharp is ahead of rage here |
| Plugin recipients | ✅ | ✅ | ✅ | stdin/stdout protocol for `age-plugin-*` binaries |

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
| Random-access decryption (`DecryptReaderAt`) | ✅ | ❌ | ✅ | Seek into encrypted files (e.g. ZIP in age) |
| Detached header APIs | ✅ | ❌ | ✅ | Extract/decrypt header separately |
| `age-inspect` | ✅ | ❌ | ✅ | Metadata inspection without decryption |
| Pull-based encryption (`EncryptReader`) | ✅ | ✅ | ✅ | Stream-returning API, lazy payload encryption/decryption |
| Async I/O | ❌ | ✅ | ❌ | Rust-specific feature flag |

## CLI Tools

| Feature | Go | Rust | AgeSharp |
|---|:---:|:---:|:---:|
| `age`/`rage` encrypt/decrypt CLI | ✅ | ✅ | ✅ |
| `age-keygen`/`rage-keygen` | ✅ | ✅ | ✅ |
| `rage-mount` (FUSE) | ❌ | ✅ | ❌ |

## Summary

AgeSharp is the most complete non-Go implementation of the age encryption specification. It covers every recipient type (including post-quantum ML-KEM-768 and the plugin protocol), all core encryption features, and all Go v1.3.0 advanced APIs — detached headers, pull-based streams, random-access decryption, and `age inspect`. AgeSharp leads rage in both post-quantum support and advanced API coverage.
