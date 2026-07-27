# Brief: find everything that must be backported from `next-version` to `main`

## Situation

`/Users/pscheid/Projects/AgeSharp` — a .NET 10 implementation of the age encryption format
(`age-encryption.org/v1`).

- **`main` (c295c10)** is the v0.2 line. It is what is published on NuGet: `0.2.0-preview.3`,
  seven prereleases, ~625 downloads total. Real people install this.
- **`next-version` (dc3faf0)** is 109 commits ahead — a v0.3 API rewrite that is **being
  abandoned** and redesigned from scratch. It will not ship.

So v0.2 is the only living version for the foreseeable future, and every bug fixed on
`next-version` that still exists on `main` is a bug in the only thing anyone can install.

**Your job: find all of them.** Produce a confirmed, reproducible list. Do not fix anything.

## The hard constraint

Backports **must not change public API**. A v0.2 user has to be able to update the package
without editing a line of their code. `next-version` contains 39 `*REMOVED*` entries in
`Age/PublicAPI.Unshipped.txt` — that entire redesign is off-limits. You are looking for
behaviour fixes only.

If a fix is entangled with an API change on `next-version`, say so, and describe the
API-neutral form the fix would take on `main`'s code shape.

## Why this is harder than reading `git log`

Two traps, both already hit:

**Commit messages are unreliable.** `git log --grep='fix\|bug\|zero\|leak'` over
`main..next-version` returns ~60 commits, and most are API redesign, not defects.

**The buggy file may not exist on `main`.** The armor padding bug (#7 below) was fixed in
`Age/Format/ArmorDecoder.cs` — a file that does not exist on `main` at all. `main` has the
same defect in `Age/Format/DearmorStream.cs`. **You cannot enumerate the set from the diff.**
You have to establish what `main`'s code actually does.

**Verify, do not infer.** In the session that produced this brief, a claim that "the all-zero
X25519 check is missing on main" turned out to be wrong — it was grepped in `CryptoHelper.cs`,
where v0.3 *centralised* it, while `main` has the check inline and present in 3 of its 5
agreement sites. Check every site, not the place you expect the code to be.

## Method — strongest evidence first

### 1. Differential testing (do this first)

`main` and `next-version` both claim to implement the same format. Anything `next-version`
handles that `main` does not is a defect, mechanically and without judgement.

```sh
git worktree add --detach /tmp/main-wt main
```

Two corpora are API-independent and therefore run against both branches unmodified:

- **`testdata/`** — 143 Community Cryptography Test Vectors (on `next-version` these live at
  `Age.TestKit/testdata`). Each is a complete age file with an expected outcome. These are
  black-box: header parsing, armor, stanza handling, chunk sequencing.
- **The reference CLI** — `age` v1.3.1 is on `PATH`. Round-trip both directions, across a
  sweep of payload sizes, armored and binary, for every recipient type. Size sweeps matter:
  defect #7 only appears at specific sizes mod 48.

`next-version`'s own unit tests will *not* compile against `main` — they use the v0.3 API.
Do not waste effort porting them wholesale; extract the black-box cases.

### 2. Targeted reading (for what tests cannot see)

Some defects are invisible to behaviour:

- **Secret zeroing.** A key that is never cleared produces identical output. Only reading
  finds these. Compare every site that touches key material — file key, payload key, wrap
  key, shared secrets, passphrases, plaintext buffers — against its `next-version` form.
- **Spec MUSTs with no vector coverage.** Read `docs/spec/age.md` and
  `docs/spec/age-plugin.md` and check each MUST against `main`. Several are not exercised by
  any test vector.
- **Plugin protocol behaviour.** No vector covers it; it needs a scripted fake plugin or
  careful reading against `docs/spec/age-plugin.md`.

## Already confirmed — verify these, then go beyond them

Each was found by inspecting `main` directly. Confirm independently; correct me if wrong.

| # | file on `main` | defect | kind |
|---|---|---|---|
| 1 | `Age/Crypto/XWing.cs`, `Age/Crypto/HpkeHelper.cs` | **0** `ZeroMemory` calls (vs 4 each on `next-version`). The entire post-quantum path leaves every intermediate secret in the GC heap — seeds, HPKE PRK, shared secrets. | secret hygiene |
| 2 | `Age/Recipients/SshEd25519Identity.cs`, `SshEd25519Recipient.cs` | X25519 agreement with **no all-zero / low-order rejection**. `X25519Identity`, `X25519Recipient` and `XWing` do have it; only the ssh-ed25519 pair does not. Spec requires it. | security |
| 3 | `Age/Recipients/PluginRecipient.cs` | `result = ParseRecipientStanza(args, body);` — **assignment, not append**. A plugin returning several `recipient-stanza`s yields a header containing only the last. Silent data loss: intended recipients cannot open the file. | correctness |
| 4 | `Age/Crypto/CryptoHelper.cs` | `HkdfDerive` passes `ikm.ToArray()` to BouncyCastle and never zeroes the copy; no `finally`. | secret hygiene |
| 5 | `Age/Recipients/ScryptRecipient.cs` | **0** `ZeroMemory`, and the type is not `IDisposable`. The passphrase is never cleared. | secret hygiene |
| 6 | `Age/Plugin/PluginConnection.cs` | `WriteStanza` does `Base64Unpadded.Encode(body)` → the wrapped **file key exists as an unclearable `string`** on the managed heap. | secret hygiene |
| 7 | `Age/Format/DearmorStream.cs` | `if (line.Length == ColumnsPerLine && bytesWritten != MaxDecodedPerLine) throw` — a final armor line of exactly 64 chars *carrying padding* is valid (46 bytes → 64 chars ending `==`, 47 → 64 ending `=`). **Rejects ~4% of valid armored files** as malformed. Pure interop failure. | interop |

Assume this list is **incomplete**. Items 3 and 7 were both found by accident.

## Areas worth specific attention

- **Every X25519 agreement site** (5 on `main`) — not just the ones you expect.
- **Armor**, both directions, at every size mod 48 — #7 suggests the geometry was not
  thought through.
- **Chunk boundaries** — 0 bytes, exactly 64 KiB, 64 KiB ± 1, multi-chunk. The empty-final-chunk
  rule and truncation detection.
- **The plugin path end to end** — it is the least covered code in the repo.
- **Error paths** — secrets leaked when an operation throws partway. `next-version` fixed
  several of these (`fileKey` unzeroed on a decrypt error path, plaintext left in an
  unzeroed `MemoryStream`).
- **Async vs sync divergence** — a recurring bug source in this codebase; the two paths were
  separately implemented.

## Reference material, all local

- `docs/spec/age.md`, `docs/spec/age-plugin.md` — vendored specs, authoritative
- `references/go-age/` — clone of `filippo.io/age`, the reference implementation
- `references/rust-age/` — clone of the Rust `age` crate (rage)
- `testdata/` — the 143 CCTV vectors
- `age` v1.3.1 on `PATH`

Where `main` disagrees with **both** reference implementations, that is strong evidence of a
defect. Where the two references disagree with each other, follow the spec and say so.

## Deliverable

Write `docs/BACKPORT_0.2.md`. For each defect:

1. **Location** — `file:line` on `main`
2. **What is wrong** — one or two sentences
3. **Reproduction** — a failing test, a CLI transcript, or exact steps. For zeroing defects,
   which secret survives and for how long. **Mark anything you could not reproduce as
   unverified** rather than presenting it as confirmed.
4. **Severity** — security / correctness / interop / hygiene, and who is affected
5. **API-neutral?** — yes, or what the API-neutral form on `main` looks like
6. **Fix shape** — the minimal change, and the `next-version` commit it corresponds to if any

End with two lists: **backport** and **do not backport** (with reasons — API churn, v0.3-only
code, not worth the risk).

Order the backport list by severity. Be explicit about your confidence in each item.
