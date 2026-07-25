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
| Seekable decryption (`Age.DecryptReader`) | ✅ | ❌ | ✅ | Seek into encrypted files (e.g. ZIP in age) |
| Random access through ASCII armor | ❌ | ✅ | ✅ | Offset translation over the fixed armor geometry. rage scans to find the end; AgeSharp probes both ends instead, so opening stays O(1) |
| Detached header APIs | ✅ | ❌ | ✅ | Extract/decrypt header separately |
| `age-inspect` | ✅ | ❌ | ✅ | Metadata inspection without decryption |
| Push-based encryption (`EncryptWriter`) | ✅ | ✅ | ✅ | Writable stream (`WriteCloser`-style); plaintext in, ciphertext out |
| Push-based decryption (`DecryptWriter`) | ❌ | ❌ | ✅ | Writable stream; ciphertext in, plaintext out. Go's `Decrypt` and rage's `Decryptor::decrypt` both return readers only |
| Pull-based streaming (`EncryptReader` / `DecryptReader`) | ✅ | ✅ | ✅ | Stream-returning API, lazy payload encryption/decryption |
| Async I/O | ❌ | ✅ | ✅ | `EncryptAsync`/`DecryptAsync`/`DecryptReaderAsync` + async streams; no blocking I/O (`AllowSynchronousIO = false`) |

## CLI Tools

| Feature | Go | Rust | AgeSharp |
|---|:---:|:---:|:---:|
| `age`/`rage` encrypt/decrypt CLI | ✅ | ✅ | ✅ |
| `age-keygen`/`rage-keygen` | ✅ | ✅ | ✅ |
| `rage-mount` (FUSE) | ❌ | ✅ | ❌ |

## Summary

AgeSharp is the most complete non-Go implementation of the age encryption specification. It covers every recipient type (including post-quantum ML-KEM-768 and the plugin protocol), all core encryption features, and all Go v1.3.0 advanced APIs — detached headers, push and pull streams, random-access decryption, and `age inspect` — plus a fully asynchronous surface (`EncryptAsync`/`DecryptAsync`/`DecryptReaderAsync` with no blocking I/O). It leads rage in post-quantum support and advanced API coverage, and matches rage's async story that the Go reference does not offer.
