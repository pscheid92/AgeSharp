# API freeze review — reading guide

The v0.3.0 tag freezes the public surface: everything in `Age/PublicAPI.Shipped.txt` plus
`Age/PublicAPI.Unshipped.txt`, minus the `*REMOVED*` entries. Until the tag, renames and removals
are free. After it, every change is a breaking change.

This guide orders the reading by **decision weight** — the things hardest to change later come
first — and pre-seeds each stop with the questions this session already surfaced. Budget ~2.5 hours.

**Progress: 7 of 27 closed** (26 pre-seeded, plus `IIdentity.Unwrap`, which the review surfaced
rather than anticipated). Decided items are checked off in place and recorded in the table at the
end. Stop 1's contracts are done bar one; Stop 2's surface shrank from ~50 members to 21, so it
reads faster than its 40-minute budget.

**What this review keeps finding is bugs, not taste.** Four of the seven closed questions had a
functional defect underneath: `Wrap` was silently dropping plugin stanzas, `IIdentityWithRecipient`
looked thin because its key implementor was missing a specified capability, `IPluginCallbacks`
led to an entire post-quantum path that zeroed nothing, and `Unwrap`'s shape was the reason
callers had a zeroing obligation at all. Treat the remaining questions the same way: ask what the
shape implies about behaviour, then check the behaviour, rather than deciding on aesthetics.

Three tools did most of the work, and are worth reaching for on every remaining question:
the reference checkouts (`go-age/`, `rust-age/`) for "what do they do here", the vendored spec in
`docs/spec/` for what is actually required, and absence queries — `grep -c` for a convention,
per file — for what a file *doesn't* do.

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
  unzeroable `string`. Consistent with the library's hygiene stance? *(Decided in principle: split
  into `RequestValue` / `RequestSecret`, the latter returning `char[]` the library clears. Not yet
  implemented — the plugin write-path zeroing goes with it.)*
- [x] **`IIdentity.Unwrap` returned a `byte[]` the caller had to zero** → **reshaped to
  `bool TryUnwrap(Stanza, Span<byte> fileKey)`**. Not on the original list; it came out of asking
  how to stop callers forgetting to zero. The caller supplies the buffer, so no ownership crosses
  the boundary, the file key can live on the stack rather than the GC heap, and the length is
  structural — the facade's `fileKey.Length != 16` check is gone, and a wrong-size return is
  unrepresentable. `Age.FileKeySize` is public now, since implementors need it.

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
- [x] **Async coverage is partial** → **correct by rule, one gap filled**. A factory needs an async
  form only when its *setup* does I/O. Probed against a stream that throws on any synchronous
  call: `EncryptReader`, `EncryptWriter` and `DecryptWriter` construct without touching it, and the
  streams they return are async all the way down (armored paths included) — so async variants of
  those would wrap a constructor that never blocks. `DecryptReader` and `ReadHeader` do read at
  setup; the first already had `DecryptReaderAsync`, the second now has `ReadHeaderAsync`. Rule
  recorded in CLAUDE.md so the asymmetry is not read as an oversight.
- [x] **No `ReadHeaderAsync`, no `*DetachedAsync`** → **all three added**. Detached is staying, and
  the async rule applies to it: whole operations doing I/O throughout, so they qualify exactly as
  `Encrypt`/`Decrypt` do.
- [x] **`DecryptIdentities(Stream, string passphrase, …)`** → **removed, replaced by
  `EncryptedIdentityFile : IIdentity`**. Worse than the question suggested: four lines leaked four
  times — the `Passphrase` it constructed was never disposed, the output buffer and its `ToArray`
  copy were never zeroed, and the identity file became an unzeroable string. Following Go's
  `EncryptedIdentity`, the file is now an identity in its own right that decrypts lazily on first
  use, which also fixes a usability flaw the old shape could not express: several `-i` files no
  longer prompt for all of them, only for the one that opens the message.
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

- [x] `AgeDecryptOptions` knobs, defaults, names → **knobs and names kept; `MaxArmorLineBytes`
  default 64 KiB → 1 KiB**. Neither reference exposes limits at all — Go bounds a stanza body line
  because the format requires it and otherwise leans on `bufio`; there is no total-header cap
  anywhere. So these are AgeSharp's own defence and have no precedent to copy, which is fine: a
  parser reading hostile input *before* authentication should bound it. But an armor line is fixed
  at 64 characters by the format and `ArmorDecoder` already rejects anything wider, so 64 KiB was
  guarding one thing only — an unterminated line, i.e. a stream that is not armor at all. 1 KiB is
  still sixteen times the spec. The header knobs stay: header lines legitimately vary (a plugin
  stanza can be long) and the total cap is the real memory bound.
- [x] `AgeEncryptOptions` has exactly one member → **confirmed, no change**. One member looks thin
  but is the right one, and the type is what lets options grow later without touching a single
  signature. Init-only properties extend compatibly, so the bar was only whether `Armor` is right.
  It is.
- [x] **`AgeHeader` is unverified data / `PayloadOffset` semantics** → **name kept, `PayloadOffset`
  reshaped to `long?`**. On the name: `ReadHeader` is the only way to obtain one, so the warning
  belongs on the method, and `UnverifiedAgeHeader` reads as ceremony at every use site. On the
  offset: for armored input it counted dearmored bytes, which are not positions in the file the
  caller holds — seeking there lands in the wrong place. It is null for armored input now, so the
  unusable case is unrepresentable rather than documented. That immediately surfaced a real bug:
  the CLI's `inspect` subtracted that dearmored offset from the armored file size and printed a
  size breakdown that looked plausible and was wrong.
- [x] `Stanza` shapes → **confirmed, no change**. `ReadOnlyMemory<byte>` rather than `Span` because
  a `Stanza` outlives a stack frame; read-only on both because a stanza is a parsed record. The
  constructor's framing validation is load-bearing, not defensive: it is the extension point custom
  recipients build on, and a newline in a type or arg would let one forge header lines.

## Stop 4 — key material (40 min) · six parallel types

Read **one pair deeply as the model**: [X25519Recipient.cs](../Age/Recipients/X25519Recipient.cs)
and [X25519Identity.cs](../Age/Recipients/X25519Identity.cs). Then check the other five against
this grid rather than re-reading each in full:

**Filled in — identities:**

| | Generate | Parse | TryParse | IParsable | ToString safe | ToSecretString | Dispose |
|---|---|---|---|---|---|---|---|
| X25519Identity | ✓ | ✓ | ✓ | ✓ | ✓ redacted | ✓ | ✓ |
| MlKem768X25519Identity | ✓ | ✓ | ✓ | ✓ | ✓ redacted (truncated) | ✓ | ✓ |
| SshEd25519Identity | — | ✓ | ✓ | — | ✓ *by default* | — | ✓ |
| SshRsaIdentity | — | ✓ | ✓ | — | ✓ *by default* | — | ✓ |
| Passphrase | — | — | — | — | ✓ *by default* | — | ✓ |
| PluginIdentity | — | ctor | — | — | ✓ (plugin name only) | ✓ | default no-op |

**Filled in — recipients:**

| | Parse | TryParse | IParsable | ToString round-trips |
|---|---|---|---|---|
| X25519Recipient | ✓ | ✓ | ✓ | ✓ |
| MlKem768X25519Recipient | ✓ | ✓ | ✓ | ✓ |
| SshEd25519Recipient | ✓ | ✓ | — | ✓ *(added — printed the type name)* |
| SshRsaRecipient | ✓ | ✓ | — | ✓ *(added — printed the type name)* |
| PluginRecipient | ctor | — | — | ✓ |

Fill in the `?` cells as you read — every `ToString` on a secret-holding type must redact.

- [x] SSH types skip `IParsable` → **confirmed**. The better reason is not the multi-line input —
  a PEM blob is still a string — but that `IParsable` implies a round-trip with `ToString`, and an
  SSH *identity* has no text form to round-trip to (no `ToSecretString`, deliberately: re-exporting
  someone's SSH private key is not this library's job).
- [x] **`ToString` on every secret-holding type** → **all six safe**, but three only by accident:
  `SshEd25519Identity`, `SshRsaIdentity` and `Passphrase` have no override, so they inherit
  `object.ToString`, which leaks nothing. Safe-by-default rather than safe-by-design; worth knowing
  if anyone adds one later.
- [x] **SSH *recipients* had no `ToString` at all** → **added**. Not on the original list. Three of
  five recipients returned their canonical text (`age1…`, the plugin string) while the two SSH ones
  printed `AgeSharp.SshEd25519Recipient` — not displayable, not round-trippable, and a silent trap
  for anything listing recipients. Both now emit their `authorized_keys` line, which `Parse`
  accepts back. `SshRsaRecipient` had to start retaining the wire bytes it previously used once and
  discarded.
- [x] `Passphrase` implements both `IRecipient` and `IIdentity` → **fine as named**. It genuinely is
  its own inverse, and any name stating one role would misdescribe the other. The doc already opens
  with "the same passphrase encrypts and decrypts, so pass the same instance to both".
- [x] `Passphrase(string, int workFactor = 18)` → explicit overloads → **confirmed**. Default
  arguments compile into caller binaries, so a changed default would not reach already-built
  callers. Every remaining default on the surface is `= null` or `= default(CancellationToken)`,
  where the value carries no policy — the meaning is resolved inside the method.
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
| `Encrypt`/`Decrypt` + the streaming grid + `Detached` + `ReadHeader` | **reshape** → one method each | ~50 entry points became 21; one call shape across sync and async. `4fc862b` |
| `EncryptDetached` options | **keep** (none) | Armor wraps a whole age file, which a detached pair is not. |
| Empty recipient list from `Wrap` | **reject** | Newly representable once `Wrap` returned a list; silently writing a header without that recipient is the same failure the reshape fixed. |
| `IIdentity.Unwrap` | **reshape** → `bool TryUnwrap(Stanza, Span<byte>)` | No ownership crosses the boundary, the file key stays off the GC heap, and its length becomes structural rather than checked. `1db7e89` |
| `IIdentityWithRecipient` | **keep** | age's third-party identities arrive as plugins, and the spec makes encrypting to a plugin identity first-class. Its key implementor was missing, not its purpose. `22887a1` |
| `IIdentity : IDisposable` + default `Dispose` | **keep** (interface, not a base class) | A base class would impose single inheritance on an extension point; dropping `IDisposable` risks unzeroed secrets. The DIM quirk is a one-time compile error, now documented. `7af5f67` |
| `IRecipientWithLabels.WrapWithLabels` | **reshape** → `LabelledStanzas` (`readonly struct`) | Widened to a stanza list with `Wrap` (`fd16800`), then the tuple replaced outright (`fb3ca67`): implementors had to reproduce a 110-char signature. `record struct` rejected — value equality over a collection compares references. |
| `Labels` as `IReadOnlyCollection` (not `IReadOnlySet`) | **keep** | `SetEquals` would honour the *implementor's* comparer; the spec requires exact, case-sensitive comparison, so the facade forces `StringComparer.Ordinal` instead of trusting it. |
| **Detached (`EncryptDetached`/`DecryptDetached`)** | **KEEP — settled, do not re-open** | Raised repeatedly during this review and answered the same way every time. It is implemented, tested, documented, and the maintainer wants it. The absence of a Go/rage equivalent is not an argument against it. |
| `Age.ReadHeaderAsync` | **add** | `ReadHeader` performs synchronous reads, so an async caller inspecting a header had no non-blocking path. `d86b957` |
| `EncryptDetachedAsync` / `DecryptDetachedAsync` | **add** | Detached is staying, and these are whole operations doing I/O throughout — the same rule that justifies `EncryptAsync`. |
| Async coverage generally | **correct by rule** | Async factories exist exactly where setup does I/O; the other three never touch a stream at construction. Rule in CLAUDE.md. |
| `Age.DecryptIdentities` | **remove** → `EncryptedIdentityFile` | Leaked four ways in four lines, and the eager shape forced a passphrase prompt per `-i` file regardless of which one matched. |
| `AgeDecryptOptions` knobs and names | **keep** | No reference exposes limits; bounding pre-authentication input is right, and the names say what they bound. |
| `MaxArmorLineBytes` default | **64 KiB → 1 KiB** | Armor lines are fixed at 64 chars and already rejected above that; the allowance only bounds an unterminated line. |
| `AgeEncryptOptions` | **keep** | `Armor` is the right member, and init-only properties let the type grow compatibly. |
| `AgeHeader` name | **keep** | `ReadHeader` is the only source, so the warning belongs on the method. |
| `AgeHeader.PayloadOffset` | **reshape** → `long?` | Meaningless for armored input; null makes that unrepresentable. Surfaced a real CLI bug on the way. |
| `Stanza` shapes | **keep** | `ReadOnlyMemory` because a stanza outlives a frame; constructor validation guards header framing at the extension point. |
| SSH recipient `ToString` | **add** | Two of five recipients printed their type name instead of their `authorized_keys` line — undisplayable and not round-trippable. |
| SSH types skipping `IParsable` | **keep** | `IParsable` implies a `ToString` round-trip, and SSH identities deliberately have no text form. |
| `Passphrase` name / dual role | **keep** | It is genuinely its own inverse; naming either role would misdescribe the other. |
| `Passphrase` explicit work-factor overloads | **keep** | Default arguments bake into caller binaries; the remaining defaults are all `null`/`default`, which carry no policy. |
| `IPluginCallbacks.RequestValue` | **decided, not yet built** | Split into `RequestValue` / `RequestSecret(→ char[])`, matching rage. Blocked on nothing; the plugin write-path zeroing lands with it. |
| *(next: `IPluginCallbacks` split + plugin write-path zeroing, `TryParse*` callbacks, `AgeHeader` naming)* | | |

Mechanics afterwards:

- Renames/removals: apply them, and the PublicAPI analyzer will force the txt files to match.
- At the tag: move the contents of `PublicAPI.Unshipped.txt` into `PublicAPI.Shipped.txt` (and
  drop the `*REMOVED*` lines from Shipped). From then on the analyzer treats the union as the
  contract.
