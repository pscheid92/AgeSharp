# API freeze review — reading guide

The v0.3.0 tag freezes the public surface: everything in `Age/PublicAPI.Shipped.txt` plus
`Age/PublicAPI.Unshipped.txt`, minus the `*REMOVED*` entries. Until the tag, renames and removals
are free. After it, every change is a breaking change.

This guide orders the reading by **decision weight** — the things hardest to change later come
first — and pre-seeds each stop with the questions this session already surfaced. Budget ~2.5 hours.

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

- [ ] **`Wrap` returns ONE `Stanza`.** Go and rage both return a *list* (`[]*Stanza`,
  `Vec<Stanza>`), and rage's docs name the use cases: multi-format recipients, group aliases,
  proxies. AgeSharp's single-stanza shape cannot express those. Widening later is breaking;
  widening now is free. Decide knowingly.
- [ ] **`IIdentityWithRecipient` is AgeSharp's own invention** — neither Go nor rage has an
  interface for identity→recipient; both put a method on the concrete types only. Keeping it buys
  the CLI's type-switch-free dispatch and lets custom identities participate. Cutting it matches
  the references. (Discussed at length this session; decide and record.)
- [ ] `IIdentity : IDisposable` with a default no-op `Dispose` — default interface methods have
  versioning quirks and not every consumer language sees them. Still comfortable?
- [ ] `IRecipientWithLabels.WrapWithLabels` returns a named tuple. Tuples in interface signatures
  are rare in the BCL. Alternative: an out param, or a small result type. Worth it, or fine?
- [ ] `IPluginCallbacks.RequestValue(prompt, secret) -> string` — a secret prompt returning an
  unzeroable `string`. Consistent with the library's hygiene stance?

## Stop 2 — the facade matrix (40 min) · the biggest surface

Files: [Age/Age.cs](../Age/Age.cs), [Age/Age.Async.cs](../Age/Age.Async.cs),
[Age/Age.Parsing.cs](../Age/Age.Parsing.cs). Signatures and docs only — the bodies are reviewed
code.

First, draw the grid yourself (operations × shapes). It should come out as: seven operations
(`Encrypt`, `Decrypt`, `EncryptReader`, `EncryptWriter`, `DecryptReader`, `DecryptWriter`,
`EncryptDetached`/`DecryptDetached`), each in `(first, params rest)` and collection shapes, with
and without options; `Encrypt`/`Decrypt` additionally in `byte[]` one-shot form; three `*Async`
methods; `ReadHeader`; and the parsing group. If your grid disagrees with the surface, one of you
is wrong — find out which.

Pre-seeded questions:

- [ ] **Async coverage is deliberately partial**: only `EncryptAsync`, `DecryptAsync`,
  `DecryptReaderAsync`; collection-shape only; options as optional trailing parameter — while sync
  takes options as a *required positional* before the recipients. Two conventions in one class.
  The `params ReadOnlySpan` overloads *cannot* be async (spans can't cross awaits), so the missing
  async params-shapes are forced — but the options-convention split is a choice. Confirm it.
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
- [ ] `EncryptDetached` has no options overload — deliberate and documented (armor wraps a whole
  file, which a detached pair is not). Confirm you still agree.

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
- [ ] **Behaviour note for the release notes**: `X25519Recipient.Wrap` now throws
  `AgeFormatException` (was `AgeException`) on a low-order recipient point — changed in this
  session's review-fix pass.

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

| Entry | Decision (keep / rename / reshape / remove / make-internal) | Why |
|---|---|---|
| | | |

Mechanics afterwards:

- Renames/removals: apply them, and the PublicAPI analyzer will force the txt files to match.
- At the tag: move the contents of `PublicAPI.Unshipped.txt` into `PublicAPI.Shipped.txt` (and
  drop the `*REMOVED*` lines from Shipped). From then on the analyzer treats the union as the
  contract.
