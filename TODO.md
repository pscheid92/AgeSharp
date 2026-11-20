# TODO

From the comparison against go-age v1.3.2, rage 0.12.1 and the other age
implementations (2026-11-17; still the latest go-age and rage releases on
2026-11-19). See [docs/FEATURE_COMPARISON.md](docs/FEATURE_COMPARISON.md).

## Shipping

- [x] Release `main` as `0.2.0-preview.5` — tagged 2026-11-18 on e3db35d, with #91–#102 and upgrade notes in the GitHub release
- [x] Release `main` as `0.2.0-preview.6` — tagged 2026-11-19 on b9920e8, with #103 (CLI removed) and #104 (tagged recipients); the package from nuget.org passed the smoke test against go-age and its `age-plugin-tagtest`
- [x] Release `main` as `0.2.0-preview.7` — tagged 2026-11-19 on 1f52f1d, with #105–#107 (legacy PEM SSH keys); the package from nuget.org passed the smoke test, legacy PEM included
- [x] ~~Multi-target `net8.0` alongside `net10.0`~~ — dropped: .NET 8 and 9 reached end of support on 2026-11-10
- [x] Clear NU1903 on the AOT publish (`Microsoft.DotNet.ILCompiler` 10.0.0) — moot: releases no longer build AOT binaries, and the preview.5 build, the last that did, logged no NU1903
- [x] Refresh `docs/BENCHMARKS.md` — rerun 2026-11-19 at preview.6, with the tagged recipients added; the BouncyCastle ChaCha20 benchmark no longer reuses a nonce at 64 KiB, which had made it fail

## Features (additive)

AgeSharp is a library; the command-line tool was removed (use `age` or `rage`).

- [x] Passphrase-protected SSH keys (OpenSSH format) — PR #100; review follow-ups in their own PR
  - Decryption (bcrypt_pbkdf and the ciphers) is SSH.NET's: neither .NET nor BouncyCastle has bcrypt_pbkdf, and a hand-written one was dropped in favour of a widely used library
  - AgeSharp still reads the container itself (the public key, so the passphrase is asked for only when needed). Once a file matches, and before asking, it refuses what it cannot decrypt: an unknown cipher or KDF, or more than 2048 bcrypt rounds (Go's cap, which Go also applies only at decryption). It checks what SSH.NET returns: the public key must match, and RSA keys get Go's checks (n = p·q, e·d ≡ 1 mod p−1 and q−1, an odd exponent of 3 to 24 bits, size limits), with their CRT values recomputed
  - Blazor WebAssembly (checked 2026-11-18, Release build): ssh-ed25519 keys with aes256-gcm or ChaCha20-Poly1305 decrypt. Every other protected key is refused before the passphrase prompt: SSH.NET uses the platform's AES, 3DES and RSA, and the browser has none of them
  - [x] Ask SSH.NET upstream to fall back to BouncyCastle (which it already depends on) where the platform has no AES, 3DES or RSA — sshnet/SSH.NET#1870
  - [ ] Once an SSH.NET release has those fallbacks, widen the browser allowlist (`ProtectedOpenSshKey.WhyItCannotBeDecryptedInTheBrowser`) to match, keeping 3des-cbc refused unless it is fixed too, and re-check in Blazor WebAssembly
- [x] Passphrase-protected SSH keys in the legacy PEM format: `AgeKeygen.ParseSshIdentity(pemText, publicKey, passphrase)` with the `.pub` file, as go-age reads them; AES-128/192/256-CBC and 3DES, decrypted by SSH.NET. Single DES is refused before the passphrase is asked for (go-age reads it; SSH.NET does not), and encrypted PKCS#8 is refused as in go-age
- [x] Unprotected OpenSSH keys that BouncyCastle's reader refuses but OpenSSH and go-age read (8 or more bytes of padding, a comment ending in a byte 0x01–0x07, numbers with a redundant leading zero): SSH.NET now reads what BouncyCastle refuses, with the same checks after. In the browser the ed25519 ones work; an RSA one stays refused there, as before (SSH.NET needs the platform's RSA)
- [x] Native tagged recipients: `age1tag1…` (p256tag) and `age1tagpq1…` (mlkem768p256tag), encryption only — HPKE on BouncyCastle, checked against RFC 9180 and draft-ietf-hpke-pq vectors and go-age's tag test identities
- [ ] `PluginIdentity` as `IIdentityWithRecipient`: its recipient speaks recipient-v1 with `add-identity`, so a file can be encrypted to the identities in a key file, plugins included (recorded on `next-version`; deferred from rebuild step 1)
- [ ] AgeSharp's own identities derive the file key straight into the caller's buffer, instead of recovering it into an array and handing that over zeroed (`FileKey.Deliver`)
- [ ] Plugin connection: write stanzas to the plugin's stdin as bytes, not through a `StreamWriter`, whose internal buffer keeps a copy of the last body written (a file key, or a secret since rebuild step 2) until it is overwritten
- [ ] Plugin recipients: advertise `extension-labels` and pass a plugin's labels on through `IRecipientWithLabels` (possible since rebuild step 1; today a plugin is told nothing and sends none)
- [ ] Plugin authoring: the server side of the plugin protocol
- [ ] Small differences from go-age (low priority): a matching stanza without arguments is an error in go-age and skipped here; an even RSA exponent is refused with BouncyCastle's own message

## Tagged recipients, later (from the #104 review)

- [x] One injectable random source for the KEMs, instead of the encapsulation overloads that exist for the known-answer vectors — every `Encapsulate` takes a `SecureRandom`; the vectors pass theirs as a fixed one
- [x] One ML-KEM-768 encapsulation-key type shared by X-Wing and MLKEM768-P256 (decoding is repeated four times), and one hybrid combiner taking its label — `MlKem768EncapsulationKey` and `HybridKem.CombineSharedSecrets`. BouncyCastle 2.7.0 checks the coefficients itself now, so AgeSharp's own check is gone; tests at the boundary pin BouncyCastle's
- [x] Naming: `XWing.KemId` / `DhKemP256.Id`, `Encaps` / `Encapsulate`, `PointSize` / `CompressedPointSize`; `HpkeHelper.SealBase` no longer has RFC 9180's shape — `KemId`, `Encapsulate`/`Decapsulate`, `UncompressedPointSize`, `HpkeHelper.Seal`/`Open`
- [x] ~~Cache decoded keys per recipient instead of re-decoding on every `Wrap`~~ — dropped: measured 2026-11-19, decoding is ~3% of a Wrap; the two P-256 multiplications in BouncyCastle are ~97%. A cached BouncyCastle `ECPoint` would also carry its precomputation tables, shared mutable state behind a class documented as safe to share
- [ ] Constant-time P-256 for the recipient-point multiplication (BouncyCastle 2.7.0 has no ladder multiplier)
  - The platform's `ECDiffieHellman`, with BouncyCastle kept for the browser, would give constant time and is the only real speed lever; but on macOS it measured ~465 us per exchange, about twice BouncyCastle's. Measure Linux and Windows before deciding
- [x] Release notes: `age1tag1…`/`age1tagpq1…` lines in a recipients file are now native recipients, no longer plugin recipients, and malformed ones fail when the file is parsed — in the preview.6 notes

## API (breaking — fold into the rebuild)

- [ ] Async entry points for encrypt and decrypt (design exists on `next-version`)
- [x] Peeking armor detection, so armored input is recognised on non-seekable streams too (pipes, network streams) — rebuild step 3c: `PeekableStream`; `Decrypt`, `DecryptReader` and `AgeHeader.Parse` read ahead instead of seeking
- [ ] `Passphrase` type instead of `string`, so it can be zeroed
- [x] `IRecipient.Wrap` returning several stanzas and labels; make the multi-stanza interface public — rebuild step 1: `Wrap → IReadOnlyList<Stanza>`, `IRecipientWithLabels` with `LabelledStanzas`, `IIdentity.TryUnwrap(Stanza, Span<byte>)`, `IIdentityWithRecipient`
- [ ] Split `ScryptRecipient` into recipient and identity; adjustable maximum work factor
- [ ] `NoIdentityMatchException` carrying per-identity errors and the stanza types seen
- [ ] File-key extraction and injection (`ExtractHeader`, `DecryptHeader`, injected-file-key identity)
- [ ] Public armor reader and writer
- [ ] Replace the `AgeEncrypt` / `AgeKeygen` static catch-alls with domain types
  - `AgeKeygen.ParseRecipient(string)` parses X25519 only (it returns `X25519Recipient`); a recipient string of unknown type takes `ParseRecipientsFile(line)[0]` (or the type's own `Parse` when the type is known). Until the rebuild, the README and the method's docs say so

## Internal (from the 2026-09-22 review)

- [ ] `PayloadKey` type
- [x] Shared plugin prompt handler — `Age.Plugin.PluginPrompts`, used by `PluginRecipient` and `PluginIdentity`
- [ ] Remove test-only code from the production assembly (the KEMs' scalar overloads and `PluginRecipient.WrapWithConnection` are gone; `PluginIdentity.UnwrapWithConnection` and others remain)
