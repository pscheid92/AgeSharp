# Migrating to AgeSharp 0.3

v0.3 replaces the public API wholesale with a cleaner, flatter surface. The **wire
format, crypto, and interop guarantees are unchanged** — files written by 0.2 and
0.3 are byte-compatible, and both interoperate with `age`/`rage`. This is an API
break, not a format break. There are no `[Obsolete]` shims; update call sites
directly using the table below.

## At a glance

- **One namespace.** Everything lives in `AgeSharp`. The old `Age`,
  `Age.Recipients`, `Age.Format`, and `Age.Plugin` namespaces are gone.
- **One facade.** `Age` absorbs the old `AgeEncrypt` and the parsing side of
  `AgeKeygen`. Key generation moves onto the key types themselves.
- **One decrypt stream.** `Age.OpenRead` replaces both `DecryptReader` and
  `AgeRandomAccess`: its `CanSeek` mirrors the source, so a seekable input gives
  you `Length`/`Seek` random access with a one-chunk cache.
- **New: push encryption and async.** `Age.OpenWrite` (writable stream) and
  `EncryptAsync`/`DecryptAsync`/`OpenReadAsync` are new in 0.3.
- **Coherent exceptions.** A small hierarchy under `AgeException` replaces the
  scattered `FormatException`/`AgeHeaderException`/`AgeArmorException`/
  `AgeHmacException`/`AgePayloadException`.

## Mapping table

| v0.2 | v0.3 |
|---|---|
| `using Age; using Age.Recipients; using Age.Format;` | `using AgeSharp;` |
| `AgeEncrypt.Encrypt(in, out, r)` | `Age.Encrypt(in, out, r)` |
| `AgeEncrypt.Encrypt(in, out, armor: true, r)` | `Age.Encrypt(in, out, new AgeOptions { Armor = true }, r)` |
| `AgeEncrypt.Decrypt(in, out, id)` | `Age.Decrypt(in, out, id)` |
| `AgeEncrypt.EncryptReader(pt, r)` | `Age.EncryptReader(pt, r)` |
| `AgeEncrypt.DecryptReader(ct, id)` | `Age.OpenRead(ct, id)` |
| *(no equivalent)* | `Age.OpenWrite(dest, r)` — push (writable-stream) encryption |
| *(no equivalent)* | `Age.EncryptAsync` / `Age.DecryptAsync` / `Age.OpenReadAsync` |
| *(no equivalent)* | `byte[] Age.Encrypt(ReadOnlySpan<byte>, r)` / `byte[] Age.Decrypt(ReadOnlySpan<byte>, id)` |
| `AgeEncrypt.EncryptDetached` / `DecryptDetached` | `Age.EncryptDetached` / `Age.DecryptDetached` |
| `new AgeRandomAccess(ct, id)` + `ReadAt` / `GetStream` | `Age.OpenRead(ct, id)` → seekable `Stream` (`Length`, `Seek`) |
| `AgeHeader.Parse(s)` / `.Recipients` / `.RecipientCount` | `Age.ReadHeader(s)` / `.Stanzas` / `.Stanzas.Count` |
| `AgeKeygen.Generate()` | `X25519Identity.Generate()` |
| `AgeKeygen.GeneratePq()` | `MlKem768X25519Identity.Generate()` |
| `AgeKeygen.ParseIdentity` / `ParsePqIdentity` / `ParseSshIdentity` | `Age.ParseIdentity` (universal) or the concrete type's `Parse` |
| `AgeKeygen.ParseRecipient` / `ParsePqRecipient` / `ParseSshRecipient` | `Age.ParseRecipient` (universal) or the concrete type's `Parse` |
| `AgeKeygen.ParseRecipientsFile` / `ParseIdentityFile` | `Age.ParseRecipients` / `Age.ParseIdentities` (return arrays) |
| `AgeKeygen.DecryptIdentityFile(bytes, pw)` | `Age.DecryptIdentities(stream, pw)` |
| `AgeKeygen.EncryptIdentityFile(text, pw, armor, wf)` | recipe: `Age.Encrypt(bytes, new AgeOptions { Armor = … }, new Passphrase(pw, wf))` |
| `new ScryptRecipient(pw, wf)` | `new Passphrase(pw, wf)` |
| `identity.ToString()` *(returned the secret!)* | `identity.ToSecretString()` — `ToString()` is now redacted |
| `AgeLimits.Max*` consts | `AgeOptions.Max*` init-properties (per-call) |
| `catch (FormatException)` on parses | `catch (AgeFormatException)`, or use `TryParse` |
| `catch (AgeHeaderException / AgeArmorException)` | `catch (AgeFormatException)` |
| `catch (AgeHmacException / AgePayloadException)` | `catch (AgeAuthenticationException)` |

## Notes on specific changes

**`ToString()` is now redacted.** In 0.2, `identity.ToString()` returned the secret
key string — a real footgun for logs. In 0.3 it returns a redacted form like
`X25519Identity(age1…)`; use `ToSecretString()` when you deliberately want the
exportable secret.

**Limits are per-call.** The old `AgeLimits.Max*` static constants are now
`init`-only properties on `AgeOptions`, passed to any decrypt or header-inspection
call — so different call sites can set different bounds.

**Universal parsing.** `Age.ParseRecipient` / `Age.ParseIdentity` dispatch on the
string prefix and accept every supported format (X25519, ML-KEM-768, SSH, plugin).
Call a concrete type's `Parse` when you want the concrete type back — for example to
`Dispose` an identity that holds key material.

**Random access.** Anywhere you used `AgeRandomAccess`, use `Age.OpenRead` over a
seekable stream and treat the result as a normal seekable `Stream` (`Length`,
`Seek`, `Position`). Payload truncation is only detected once a read reaches the
affected chunk — a seek-and-read that never touches the final chunk cannot observe
a truncated tail.
