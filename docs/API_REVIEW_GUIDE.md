# API freeze review — reading guide

The v0.3.0 tag freezes the public surface: everything in `Age/PublicAPI.Shipped.txt` plus
`Age/PublicAPI.Unshipped.txt`, minus the `*REMOVED*` entries. Until the tag, renames and removals
are free. After it, every change is a breaking change.

This guide orders the reading by **decision weight** — the things hardest to change later come
first — and pre-seeds each stop with the questions this session already surfaced. Budget ~2.5 hours.

**Progress: 3 of 26 questions closed.** The decided ones are checked off in place and recorded in
the table at the end; the biggest, `IRecipient.Wrap`, is done. Stop 2's surface has already shrunk
from ~50 members to 21, so it now reads faster than the 40 minutes budgeted.

The review target is signatures and doc comments, not method bodies. Read bodies only when a
signature makes you suspicious.

---

## Stop 0 — the whole surface at once (15 min)

Generate the effective frozen surface and read it top to bottom:

```bash
grep -hv '^#' Age/PublicAPI.Shipped.txt Age/PublicAPI.Unshipped.txt | grep -v '^\*REMOVED\*' | sort > api-surface.txt
grep '^\*REMOVED\*' Age/PublicAPI.Unshipped.txt | sed 's/^\*REMOVED\*//' | sort | comm -23 api-surface.txt - | less
```

Goal is the gestalt, not judgments: how big does this feel, what clusters exist, which lines make
you pause. Mark the pauses; the later stops will catch them. Delete `api-surface.txt` after.

The `*REMOVED*` list is also worth a skim — it's the record of what 0.3 already decided against
(the granular exception hierarchy, `AgeRandomAccess`, the `Label` property). If a review question
below tempts you to reintroduce one of those shapes, the answer is probably in why it was removed.

---

## Stop 1 — the contracts (20 min) · hardest to ever change

Interfaces break *implementors*, not just callers, when they change. These five files are the
deepest commitments in the freeze.

Read, in order:

1. [Age/Recipients/IRecipient.cs](../Age/Recipients/IRecipient.cs)
2. [Age/Recipients/IRecipientWithLabels.cs](../Age/Recipients/IRecipientWithLabels.cs)
3. [Age/Recipients/IIdentity.cs](../Age/Recipients/IIdentity.cs)
4. [Age/Recipients/IIdentityWithRecipient.cs](../Age/Recipients/IIdentityWithRecipient.cs)
5. [Age/Plugin/IPluginCallbacks.cs](../Age/Plugin/IPluginCallbacks.cs)

Pre-seeded questions:

- [x] **`Wrap` returns ONE `Stanza`.** → **reshaped to `IReadOnlyList<Stanza>`** (`fd16800`).
  Not just a shape question in the end: `PluginRecipient` assigned rather than appended, so a
  plugin answering one `wrap-file-key` with several `recipient-stanza`s — which `age-plugin.md`
  permits and both references accumulate — silently kept the last and dropped the rest. Proven
  with a fake plugin through the `PluginConnection` seam; test added.
- [x] **`IIdentityWithRecipient` is AgeSharp's own invention** → **kept**. The deciding evidence was
  not the pattern but the ecosystem: age's third-party mechanism is plugins, and `age-plugin.md`
  makes `(add-identity, IDENTITY)` a first-class part of `recipient-v1` — encrypting *to* a plugin
  identity is specified, and Go implements it. So the interface's most important implementor is
  `PluginIdentity`, which could not implement it because `PluginRecipient` had no identity-based
  wrap path. Fixed alongside this decision; the apparent thinness was the missing capability.
- [x] `IIdentity : IDisposable` with a default no-op `Dispose` → **kept, as an interface**. Measured
  rather than assumed: `using` over a concrete type, over `Age.ParseIdentity`, and calls through
  either interface all work; only a direct `id.Dispose()` on a concrete type that declares none
  fails to compile (CS1061). That is a loud, one-time compile error, not a silent leak.
  An abstract base class was considered — it removes the quirk entirely — and rejected: it would
  impose single inheritance on an extension point (an identity backed by a `SafeHandle` or a
  vendor SDK type could never implement it), split the symmetric pair since `IRecipient` must
  stay an interface, and break `IIdentityWithRecipient : IIdentity`. Dropping the `IDisposable`
  base was also rejected: its failure mode is unzeroed key material, which is worse than a
  compile error in a hygiene-focused library. Doc now warns implementors about the quirk.
- [x] `IRecipientWithLabels.WrapWithLabels` returns a named tuple → **replaced with
  `LabelledStanzas`**, a `readonly struct`. The deciding argument was the implementor's, not the
  caller's: this interface exists to be implemented, and a custom recipient had to reproduce a
  110-character tuple signature exactly. It is now 65. Deconstruction is preserved, so no call
  site changed. A `record struct` was rejected for one reason — its generated value equality
  compares the `IReadOnlyList` by reference, so two identical results report unequal while `==`
  invites you to ask. Not offering equality beats offering it wrongly.
  *(The "rare in the BCL" framing in the original question was weak: rage returns the same pair
  as a tuple and Go as multiple values, but both are idioms of languages that do not face this
  choice, so neither is evidence about C#.)*
- [ ] `IPluginCallbacks.RequestValue(prompt, secret) -> string` — a secret prompt returning an
  unzeroable `string`. Consistent with the library's hygiene stance?

## Stop 2 — the facade matrix (40 min) · the biggest surface

Files: [Age/Age.cs](../Age/Age.cs), [Age/Age.Async.cs](../Age/Age.Async.cs),
[Age/Age.Parsing.cs](../Age/Age.Parsing.cs), [Age/Age.Header.cs](../Age/Age.Header.cs).
Signatures and docs only — the bodies are reviewed code.

Since the consolidation this is a short list rather than a matrix: one method per operation —
`Encrypt`, `Decrypt` (each in stream and `byte[]` form), `EncryptReader`, `EncryptWriter`,
`DecryptReader`, `DecryptWriter`, `EncryptDetached`, `DecryptDetached`, `ReadHeader` — plus three
`*Async` and the six parsing members. Twenty-one in total. If your count disagrees with the
surface, one of you is wrong; find out which.

Pre-seeded questions:

- [x] **The options-convention split** → **resolved** (`4fc862b`). The facade collapsed from ~50
  methods to one per operation: recipients/identities always an `IReadOnlyList<>`, options always
  last and optional. Sync and async now share one shape, differing only by a trailing
  `CancellationToken`, so the two-conventions problem is gone. `RS0026` suppressed in `Age.csproj`
  with the reasoning recorded there.
- [ ] **Async coverage is still partial** — only `EncryptAsync`, `DecryptAsync`,
  `DecryptReaderAsync`. Separate question from the convention, and still open.
- [ ] **No `ReadHeaderAsync`**, though `ReadHeader` reads the stream. No `*DetachedAsync` either.
  Omission or decision?
- [ ] **`DecryptIdentities(Stream, string passphrase, …)`** — takes a raw `string` passphrase
  while the `Passphrase` type exists precisely because strings can't be zeroed; internally the
  decrypted identity file (containing `AGE-SECRET-KEY` lines) round-trips through an unzeroable
  string. Also the name: it *decrypts and parses*. Right shape for a hygiene-proud library?
- [ ] **`TryParseRecipient`/`TryParseIdentity` take no `IPluginCallbacks`** — a plugin string
  parsed through them silently gets null callbacks, while `ParseRecipient` accepts them.
  Asymmetry: intentional?
- [ ] `ParseRecipients`/`ParseIdentities`/`DecryptIdentities` return **mutable arrays**. The docs
  justify it (arrays convert implicitly to the `ReadOnlySpan` params overloads — a real ergonomic
  win). Confirm the trade.
- [x] `EncryptDetached` has no options parameter → **confirmed and kept** during the consolidation
  (`4fc862b`); it is the one entry point that deliberately takes none.

## Stop 3 — options and data (15 min)

Files: [Age/AgeEncryptOptions.cs](../Age/AgeEncryptOptions.cs),
[Age/AgeDecryptOptions.cs](../Age/AgeDecryptOptions.cs), [Age/AgeHeader.cs](../Age/AgeHeader.cs),
[Age/Format/Stanza.cs](../Age/Format/Stanza.cs).

- [ ] `AgeDecryptOptions`: are `MaxHeaderLineBytes` / `MaxHeaderBytes` / `MaxArmorLineBytes` the
  right three knobs, at the right defaults, under the right names? These become permanent.
- [ ] `AgeEncryptOptions` has exactly one member. Anything you already know 0.4 will need
  (it can be *added* compatibly — init-only properties extend fine — so the bar is only: is
  `Armor` right)?
- [ ] **`AgeHeader` is unverified data** — no MAC check has run when you hold one. The docs say it;
  the *name* doesn't. Is doc-only warning enough, or should the name carry it? Also
  `PayloadOffset` refers to the dearmored byte stream for armored input — subtle; keep the
  semantics or reshape before freezing.
- [ ] `Stanza`: public constructor validates header-framing safety (this is the extension point
  for custom recipients). `Body` as `ReadOnlyMemory<byte>`, `Args` as `IReadOnlyList<string>` —
  right shapes?

## Stop 4 — key material (40 min) · six parallel types

Read **one pair deeply as the model**: [X25519Recipient.cs](../Age/Recipients/X25519Recipient.cs)
and [X25519Identity.cs](../Age/Recipients/X25519Identity.cs). Then check the other five against
this grid rather than re-reading each in full:

| | Generate | Parse | TryParse | IParsable | ToString redacts | ToSecretString | Dispose |
|---|---|---|---|---|---|---|---|
| X25519 pair | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| MlKem768X25519 pair | ✓ | ✓ | ✓ | ✓ | ✓ (truncated) | ✓ | ✓ |
| SshEd25519 pair | — | ✓ (PEM / authorized_keys) | ✓ | — | ? | — | ✓ |
| SshRsa pair | — | ✓ (PEM / authorized_keys) | ✓ | — | ? | — | ✓ |
| Passphrase | — | — | — | — | ? | — | ✓ |
| Plugin pair | — | via `Age.ParseRecipient` | — | — | ? | — | ✓ |

Fill in the `?` cells as you read — every `ToString` on a secret-holding type must redact.

- [ ] SSH types skip `IParsable` (multi-line PEM input — reasonable). The `TryParse` parameter
  names (`pemText`, `authorizedKeysLine`) document the expected input. Confirm the asymmetry
  against the bech32 four is the story you want.
- [ ] `Passphrase` implements both `IRecipient` and `IIdentity`; the name states neither role.
  Fine, or does it need doc emphasis?
- [ ] The removed `Passphrase(string, int workFactor = 18)` became explicit overloads — default
  arguments bake into *caller* binaries at compile time, so removing the default was right.
  Nothing else on the surface has default args except `= null` callbacks and cancellation
  tokens. Confirm.
- [ ] **Release-note items accumulating** — carry these into the notes:
  `X25519Recipient.Wrap` now throws `AgeFormatException` (was `AgeException`) on a low-order
  recipient point; `Wrap`/`WrapWithLabels` now return `IReadOnlyList<Stanza>`; the facade
  collapsed to one method per operation, so every call site passes a collection.

## Stop 5 — exceptions (10 min)

File: [Age/Exceptions.cs](../Age/Exceptions.cs).

- [ ] Four leaf types + concrete base. Is `AgeException` being non-abstract intentional (user code
  can `throw new AgeException(...)`)?
- [ ] Ctor symmetry: which types carry the `(message, inner)` overload and which don't — is the
  asymmetry deliberate?
- [ ] The 0.2 granular hierarchy (`AgeArmorException`, `AgeHeaderException`, `AgeHmacException`,
  `AgePayloadException`) is `*REMOVED*`. The two-type split (format vs authentication) was pinned
  by `ExceptionContractTests`. Last chance to disagree.

## Stop 6 — the consumer's view (20 min)

- [ ] Skim the [README](../README.md) usage sections against the surface you just read. (The
  examples are compiled by `ReadmeExamplesTests`, so they *work* — the question is whether what
  they showcase is the API you want to commit to.)
- [ ] **The "missing" walk** — things that are internal today that a consumer might immediately
  need. Known candidates to consciously accept or reject:
  - stanza-type string constants (`"X25519"`, `"scrypt"`, …) — internal in `AgeProtocol`; a custom
    identity author writes them by hand today
  - no public armor/dearmor utility (armor exists only as an encrypt option / auto-detection)
  - no `ReadHeaderAsync` (also flagged at Stop 2)
- [ ] Name sweep against the references: AgeSharp deliberately diverged from Go/rage API shapes
  (the streaming grid instead of `NewReader`/`Decryptor`). The names were chosen on this branch
  (#84); this is a confirm-not-redesign pass.

---

## Recording decisions

Append rows as you go; this table is the review's output.

| Entry | Decision | Why |
|---|---|---|
| `IRecipient.Wrap` | **reshape** → `IReadOnlyList<Stanza>` | Matches Go and rage; the single-stanza shape was silently dropping plugin stanzas. `fd16800` |
| `IRecipientWithLabels.WrapWithLabels` | **reshape** (return type only) | Followed `Wrap`. Tuple shape itself still undecided. `fd16800` |
| `Encrypt`/`Decrypt` + the streaming grid + `Detached` + `ReadHeader` | **reshape** → one method each | ~50 entry points became 21; one call shape across sync and async. `4fc862b` |
| `EncryptDetached` options | **keep** (none) | Armor wraps a whole age file, which a detached pair is not. |
| Empty recipient list from `Wrap` | **reject** | Newly representable once `Wrap` returned a list; silently writing a header without that recipient is the same failure the reshape fixed. |
| `IIdentityWithRecipient` | **keep** | age's third-party identities arrive as plugins, and the spec makes encrypting to a plugin identity first-class. Its key implementor was missing, not its purpose. |
| `IIdentity : IDisposable` + default `Dispose` | **keep** (interface, not a base class) | A base class would impose single inheritance on an extension point; dropping `IDisposable` risks unzeroed secrets. The DIM quirk is a one-time compile error, now documented. |
| `WrapWithLabels` return shape | **reshape** → `LabelledStanzas` (`readonly struct`) | Implementors had to reproduce a 110-char tuple signature; record rejected because value equality over a collection compares references. |
| `Labels` as `IReadOnlyCollection` (not `IReadOnlySet`) | **keep** | `SetEquals` would honour the *implementor's* comparer; the spec requires exact, case-sensitive comparison, so the facade forces `StringComparer.Ordinal` instead of trusting it. |
| *(next: `DecryptIdentities`, `TryParse*` callbacks, Detached as a feature)* | | |

Mechanics afterwards:

- Renames/removals: apply them, and the PublicAPI analyzer will force the txt files to match.
- At the tag: move the contents of `PublicAPI.Unshipped.txt` into `PublicAPI.Shipped.txt` (and
  drop the `*REMOVED*` lines from Shipped). From then on the analyzer treats the union as the
  contract.
