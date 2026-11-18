# TODO

From the comparison against go-age v1.3.2, rage 0.12.1 and the other age
implementations (2026-11-17). See [docs/FEATURE_COMPARISON.md](docs/FEATURE_COMPARISON.md).

## Shipping

- [ ] Release `main` as `0.2.0-preview.5` — the published package lacks #91–#99
- [ ] Multi-target `net8.0` alongside `net10.0` (first check which .NET 10 APIs the code needs)
- [ ] Clear NU1903 on the AOT publish (`Microsoft.DotNet.ILCompiler` 10.0.0, GHSA-p3jp-9v83-76w…): move to a patched .NET 10 SDK
- [ ] Refresh `docs/BENCHMARKS.md` (last run 2026-07-23)

## Features (additive)

- [x] Passphrase-protected SSH keys (OpenSSH format) — uncommitted on `feat/encrypted-ssh-keys`
  - Decryption (bcrypt_pbkdf and the ciphers) is SSH.NET's: neither .NET nor BouncyCastle has bcrypt_pbkdf, and a hand-written one was dropped in favour of a widely used library
  - AgeSharp still reads the container itself (the public key, so the passphrase is asked for only when needed), caps bcrypt rounds at 2048 as Go does, and checks what SSH.NET returns: the public key must match, and RSA keys must satisfy n = p·q and e·d ≡ 1 (mod p−1, q−1), with their CRT values recomputed
  - Blazor WebAssembly (checked 2026-11-18, Release build): AES-GCM and ChaCha20-Poly1305 keys decrypt; AES-CTR and AES-CBC keys are refused before the passphrase prompt, because SSH.NET uses the platform's AES for them
  - [ ] Ask SSH.NET upstream to fall back to BouncyCastle's AES (which it already depends on) where the platform has none; then drop the browser refusal
- [ ] Passphrase-protected SSH keys in the legacy PEM format (go-age reads them, taking the public key from the `.pub` file; SSH.NET can decrypt them)
- [ ] Unprotected OpenSSH keys that BouncyCastle's reader refuses but OpenSSH reads: 8 or more bytes of padding (PuTTYgen pads 1–16), a comment ending in a byte 0x01–0x07, and numbers with a redundant leading zero. Protected keys go through SSH.NET, which reads these; unprotected ones still go through BouncyCastle
- [ ] Native tagged recipients: `age1tag1…` (p256tag) and `age1tagpq1…` (mlkem768p256tag), encryption only
- [ ] CLI: `-j` (data-less plugin identity)
- [ ] CLI: Windows console prompting when stdin is redirected (`CONIN$` / `CONOUT$`)
- [ ] Plugin authoring: the server side of the plugin protocol
- [ ] `age-plugin-batchpass` equivalent

## API (breaking — fold into the rebuild)

- [ ] Async entry points for encrypt and decrypt (design exists on `next-version`)
- [ ] Peeking armor detection, so the CLI stops buffering pipes (lifts the 2 GiB limit)
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
- [ ] Make the `cli` Codecov status a real gate once CLI coverage allows
