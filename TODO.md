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
- [x] Passphrase-protected SSH keys in the legacy PEM format: `SshIdentity.Parse(pemText, publicKey, passphrase)` with the `.pub` file, as go-age reads them; AES-128/192/256-CBC and 3DES, decrypted by SSH.NET. Single DES is refused before the passphrase is asked for (go-age reads it; SSH.NET does not), and encrypted PKCS#8 is refused as in go-age
- [x] Unprotected OpenSSH keys that BouncyCastle's reader refuses but OpenSSH and go-age read (8 or more bytes of padding, a comment ending in a byte 0x01–0x07, numbers with a redundant leading zero): SSH.NET now reads what BouncyCastle refuses, with the same checks after. In the browser the ed25519 ones work; an RSA one stays refused there, as before (SSH.NET needs the platform's RSA)
- [x] Native tagged recipients: `age1tag1…` (p256tag) and `age1tagpq1…` (mlkem768p256tag), encryption only — HPKE on BouncyCastle, checked against RFC 9180 and draft-ietf-hpke-pq vectors and go-age's tag test identities
- [x] `PluginIdentity` as `IIdentityWithRecipient`: `PluginIdentity.Recipient` speaks recipient-v1 with `add-identity`, as go-age's `Identity.Recipient`, so a file can be encrypted to the identities in a key file, plugins included (`EncryptedIdentityFile.GetRecipients` now returns them). Checked against go-age's `age-plugin-batchpass`
- [x] AgeSharp's own identities derive the file key straight into the caller's buffer, instead of recovering it into an array and handing that over zeroed (`FileKey.Deliver`): X25519, ML-KEM-768-X25519, `Passphrase` and SSH Ed25519 decrypt on the stack and copy out only once authenticated. SSH RSA and plugins still go through `Deliver`: BouncyCastle's RSA-OAEP returns an array, and a plugin's answer arrives as one
- [x] Plugin connection: write stanzas to the plugin's stdin as bytes, not through a `StreamWriter`, whose internal buffer keeps a copy of the last body written (a file key, or a secret since rebuild step 2) until it is overwritten: stanzas are laid out as bytes in cleared buffers and written to stdin's stream, never through `Process.StandardInput`
- [x] Plugin recipients: advertise `extension-labels` and pass a plugin's labels on through `IRecipientWithLabels` (rebuild step 8b)
- [x] Plugin authoring: the server side of the plugin protocol — `AgePlugin`, after go-age's `plugin` package (handlers that make ordinary recipients and identities, `Run` for recipient-v1 and identity-v1, the user-interaction requests, go-age's exit codes); checked in the tests against go-age's `age`, rage and AgeSharp's client, through a test plugin run as a process
- [x] Small differences from go-age: a stanza of a protected SSH key's type without arguments is malformed, as in go-age, not skipped; an even RSA exponent in a public key or a PKCS#1 key is refused in Go's words ("incorrect public exponent"), not BouncyCastle's

## Tagged recipients, later (from the #104 review)

- [x] One injectable random source for the KEMs, instead of the encapsulation overloads that exist for the known-answer vectors — every `Encapsulate` takes a `SecureRandom`; the vectors pass theirs as a fixed one
- [x] One ML-KEM-768 encapsulation-key type shared by X-Wing and MLKEM768-P256 (decoding is repeated four times), and one hybrid combiner taking its label — `MlKem768EncapsulationKey` and `HybridKem.CombineSharedSecrets`. BouncyCastle 2.7.0 checks the coefficients itself now, so AgeSharp's own check is gone; tests at the boundary pin BouncyCastle's
- [x] Naming: `XWing.KemId` / `DhKemP256.Id`, `Encaps` / `Encapsulate`, `PointSize` / `CompressedPointSize`; `HpkeHelper.SealBase` no longer has RFC 9180's shape — `KemId`, `Encapsulate`/`Decapsulate`, `UncompressedPointSize`, `HpkeHelper.Seal`/`Open`
- [x] ~~Cache decoded keys per recipient instead of re-decoding on every `Wrap`~~ — dropped: measured 2026-11-19, decoding is ~3% of a Wrap; the two P-256 multiplications in BouncyCastle are ~97%. A cached BouncyCastle `ECPoint` would also carry its precomputation tables, shared mutable state behind a class documented as safe to share
- [x] Constant-time P-256 for the tagged recipients: the exchange runs on the platform's `ECDiffieHellman`, which generates the ephemeral key, with BouncyCastle kept for the browser (and the `ForcePortableAead` test build)
  - Measured 2026-11-21 (`P256ExchangeBenchmarks`, one exchange; BouncyCastle ~250–310 us everywhere): the platform takes 120 us on Linux (x64, OpenSSL), ~490–600 us on macOS and ~1.5 ms on Windows (CNG), once per tagged recipient per file. Importing a scalar costs 50–110 ms on macOS, so only the known-answer vectors do
- [x] Release notes: `age1tag1…`/`age1tagpq1…` lines in a recipients file are now native recipients, no longer plugin recipients, and malformed ones fail when the file is parsed — in the preview.6 notes

## API (breaking — fold into the rebuild)

The rebuild is done and the public API frozen (rebuild step 8d): `PublicAPI.Shipped.txt` holds
the surface as frozen, and any change to it from here is a breaking change. Additions since
(`AgePlugin`, `PluginIdentity.Recipient`) are in `PublicAPI.Unshipped.txt` until a release.

- [ ] Release notes for the next release, on behaviour changed since the freeze: a payload cut off in its nonce is now `AgeAuthenticationException` (was `AgeFormatException`), as Decrypt documented; a wrong passphrase for an `EncryptedIdentityFile` or a protected SSH key is `AgeAuthenticationException` (was the base `AgeException`, so `catch (AgeException)` still catches it); the SSH identities' `Recipient` throws `ObjectDisposedException` after `Dispose`, as the interface says; an `EncryptedIdentityFile` whose decrypted contents are not an identity file is `AgeFormatException` (was a raw `FormatException`)
- [x] Async entry points for encrypt and decrypt: `EncryptAsync`, `DecryptAsync`, `DecryptReaderAsync`, the detached forms and the writers (rebuild steps 4b to 4d)
- [x] Before the freeze, a review of the whole surface: plugin callbacks name the plugin and may decline, `PluginRecipient.Parse`/`PluginIdentity.Parse`, plugin labels, one `Func<char[]?>` shape for passphrase sources (rebuild steps 8a to 8c)
- [x] Peeking armor detection, so armored input is recognised on non-seekable streams too (pipes, network streams) — rebuild step 3c: `PeekableStream`; `Decrypt`, `DecryptReader` and `AgeHeader.Read` read ahead instead of seeking
- [x] `Passphrase` type instead of `string`, so it can be zeroed — rebuild step 5a: `Passphrase` from a `string` or `ReadOnlySpan<char>`, keeping only UTF-8 that `Dispose` clears
- [x] `IRecipient.Wrap` returning several stanzas and labels; make the multi-stanza interface public — rebuild step 1: `Wrap → IReadOnlyList<Stanza>`, `IRecipientWithLabels` with `LabelledStanzas`, `IIdentity.TryUnwrap(Stanza, Span<byte>)`, `IIdentityWithRecipient`
- [x] Adjustable maximum work factor — `Passphrase.MaxWorkFactor` (default 22), as go-age and rage set it; the passphrase stays one type for both roles, as decided for the rebuild
- [x] Exceptions split by what went wrong: `AgeFormatException` and `AgeAuthenticationException` replace the header, armor, HMAC and payload exceptions (rebuild step 6a)
- [x] `NoIdentityMatchException` carrying per-identity errors and the stanza types seen: `StanzaTypes` and `Mismatches` (rebuild step 6b)
- [x] File-key extraction and injection (`ExtractHeader`, `DecryptHeader`, injected-file-key identity): `AgeHeader.ToBytes`, `Identities.UnwrapFileKey`, `FileKeyIdentity` (rebuild step 7)
- [x] Public armor reader and writer — `Armor.Encode` / `Armor.Decode` (rebuild step 4e)
- [x] Replace the `AgeEncrypt` / `AgeKeygen` static catch-alls with domain types
  - [x] Encrypting: `Recipients` (rebuild step 4b), with `Recipients.ParseOne` for a recipient of any type
  - [x] Decrypting: `Identities` (rebuild step 4c), with `Identities.ParseOne` for an identity of any type and the header limits as `AgeDecryptOptions`
  - [x] The writer forms: `EncryptWriter` and `DecryptWriter` (rebuild step 4d)
  - [x] The seekable reader (a seekable `DecryptReader` result in place of `AgeRandomAccess`), `AgeHeader.Read` / `ReadAsync`, and public armor (rebuild step 4e)
  - [x] `AgeKeygen`'s SSH and encrypted-identity-file members: `SshIdentity` and a lazy `EncryptedIdentityFile` (rebuild step 5b); `AgeKeygen` is gone

## Internal (from the 2026-09-22 review)

- [x] `PayloadKey` type — `AgeSharp.Crypto.PayloadKey`: derived on the stack into the cipher that the payload stream owns and disposes, so AgeSharp keeps no payload-key array of its own (the portable backend's BouncyCastle cipher still holds a copy it cannot clear, as before)
- [x] Shared plugin prompt handler — `AgeSharp.PluginPrompts`, used by `PluginRecipient` and `PluginIdentity`
- [x] Remove test-only code from the production assembly: the KEMs' scalar overloads, and the whole-buffer `StreamEncryption` helpers with the key-taking chunk overloads (now `WholePayload` in the tests). The plugin connection seams stay by design: `WrapWithConnection` and `UnwrapWithConnection` are what the library itself calls, and `PluginConnection(TextReader, TextWriter)` is how the protocol is tested without a process
