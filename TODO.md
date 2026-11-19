# TODO

From the comparison against go-age v1.3.2, rage 0.12.1 and the other age
implementations (2026-11-17). See [docs/FEATURE_COMPARISON.md](docs/FEATURE_COMPARISON.md).

## Shipping

- [x] Release `main` as `0.2.0-preview.5` — tagged 2026-11-18 on e3db35d, with #91–#102 and upgrade notes in the GitHub release
- [ ] Multi-target `net8.0` alongside `net10.0` (first check which .NET 10 APIs the code needs)
- [x] Clear NU1903 on the AOT publish (`Microsoft.DotNet.ILCompiler` 10.0.0) — moot: releases no longer build AOT binaries, and the preview.5 build, the last that did, logged no NU1903
- [ ] Refresh `docs/BENCHMARKS.md` (last run 2026-07-23)

## Features (additive)

AgeSharp is a library; the command-line tool was removed (use `age` or `rage`).

- [x] Passphrase-protected SSH keys (OpenSSH format) — PR #100; review follow-ups in their own PR
  - Decryption (bcrypt_pbkdf and the ciphers) is SSH.NET's: neither .NET nor BouncyCastle has bcrypt_pbkdf, and a hand-written one was dropped in favour of a widely used library
  - AgeSharp still reads the container itself (the public key, so the passphrase is asked for only when needed). Once a file matches, and before asking, it refuses what it cannot decrypt: an unknown cipher or KDF, or more than 2048 bcrypt rounds (Go's cap, which Go also applies only at decryption). It checks what SSH.NET returns: the public key must match, and RSA keys get Go's checks (n = p·q, e·d ≡ 1 mod p−1 and q−1, an odd exponent of 3 to 24 bits, size limits), with their CRT values recomputed
  - Blazor WebAssembly (checked 2026-11-18, Release build): ssh-ed25519 keys with aes256-gcm or ChaCha20-Poly1305 decrypt. Every other protected key is refused before the passphrase prompt: SSH.NET uses the platform's AES, 3DES and RSA, and the browser has none of them
  - [x] Ask SSH.NET upstream to fall back to BouncyCastle (which it already depends on) where the platform has no AES, 3DES or RSA — sshnet/SSH.NET#1870
  - [ ] Once an SSH.NET release has those fallbacks, widen the browser allowlist (`ProtectedOpenSshKey.WhyItCannotBeDecryptedInTheBrowser`) to match, keeping 3des-cbc refused unless it is fixed too, and re-check in Blazor WebAssembly
- [ ] Passphrase-protected SSH keys in the legacy PEM format (go-age reads them, taking the public key from the `.pub` file; SSH.NET can decrypt them)
- [ ] Unprotected OpenSSH keys that BouncyCastle's reader refuses but OpenSSH reads: 8 or more bytes of padding (PuTTYgen pads 1–16), a comment ending in a byte 0x01–0x07, and numbers with a redundant leading zero. Protected keys go through SSH.NET, which reads these; unprotected ones still go through BouncyCastle
- [x] Native tagged recipients: `age1tag1…` (p256tag) and `age1tagpq1…` (mlkem768p256tag), encryption only — HPKE on BouncyCastle, checked against RFC 9180 and draft-ietf-hpke-pq vectors and go-age's tag test identities
- [ ] Plugin authoring: the server side of the plugin protocol
- [ ] Small differences from go-age (low priority): a matching stanza without arguments is an error in go-age and skipped here; an even RSA exponent is refused with BouncyCastle's own message

## API (breaking — fold into the rebuild)

- [ ] Async entry points for encrypt and decrypt (design exists on `next-version`)
- [ ] Peeking armor detection, so armored input is recognised on non-seekable streams too (pipes, network streams); today it needs a seekable stream
- [ ] `Passphrase` type instead of `string`, so it can be zeroed
- [ ] `IRecipient.Wrap` returning several stanzas and labels; make the multi-stanza interface public
- [ ] Split `ScryptRecipient` into recipient and identity; adjustable maximum work factor
- [ ] `NoIdentityMatchException` carrying per-identity errors and the stanza types seen
- [ ] File-key extraction and injection (`ExtractHeader`, `DecryptHeader`, injected-file-key identity)
- [ ] Public armor reader and writer
- [ ] Replace the `AgeEncrypt` / `AgeKeygen` static catch-alls with domain types

## Internal (from the 2026-09-22 review)

- [ ] `PayloadKey` type
- [ ] Shared plugin prompt handler
- [ ] Remove test-only code from the production assembly
