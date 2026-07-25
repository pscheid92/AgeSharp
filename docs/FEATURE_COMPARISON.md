# Feature Completeness: AgeSharp vs Go (age) vs Rust (rage)

Verified against local checkouts of **age v1.3.1** and **rage v0.12.1**. Claims about
another project are checked against its source before being written down here, not
recalled — this file makes negative claims about third-party software, and one of
them was wrong for a while.

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

## Advanced Features

| Feature | Go | Rust | AgeSharp | Notes |
|---|:---:|:---:|:---:|---|
| Seekable decryption (`Age.DecryptReader`) | ✅ | ✅ | ✅ | Seek into encrypted files (e.g. ZIP in age). Go: `DecryptReaderAt`; rage: `impl Seek for StreamReader` |
| Random access through ASCII armor | ❌ | ✅ | ✅ | rage got here first (`impl Seek for ArmoredReader`). It scans in blocks to find the end; AgeSharp probes both ends instead, so opening stays O(1). Go's armor package exposes only a forward reader |
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

AgeSharp covers every recipient type (including post-quantum ML-KEM-768 and the plugin protocol), all core encryption features, and all of Go's advanced APIs — detached headers, push and pull streams, random-access decryption, and inspection — plus a fully asynchronous surface with no blocking I/O.

Where each implementation is ahead:

- **AgeSharp** is alone in offering push-based *decryption*, and is the only implementation with both detached headers and post-quantum recipients.
- **rage** reached random access through ASCII armor first, and offers `rage-mount` (FUSE), which neither other implementation has.
- **Go** remains the reference: it defines the format, and its plugin protocol and CLI are what everything else is measured against.

Async is available in AgeSharp and rage but not in the Go library.
