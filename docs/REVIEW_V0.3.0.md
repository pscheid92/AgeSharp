# v0.3.0 pre-tag review report

**Branch:** `next-version` (30 commits ahead of `review/p2`, 126 files / 15,915 lines vs `main`)
**Date:** 2026-07-25
**Reviewed at:** `e138704` (Documentation sweep before the tag, #90)

---

## 1. Why the branch was split

`next-version` is 27 merged PRs stacked on `main` — 126 files and 15,915 changed lines. That exceeds the cloud review's limits (500 files / 8,000 lines), so the branch was cut into three segments at PR merge boundaries, each independently reviewable:

| Part | Range | Files | Lines | Content |
|------|-------|-------|-------|---------|
| 1 | `main` → #45 (`170daf6`) | 50 | 3,067 | exception hierarchy, TryParse/IParsable, labels redesign, ssh-ed25519 guard, key-codec dedup |
| 2 | #45 → #51 (`d1c1236`) | 96 | 5,921 | namespace flatten, `Age` facade, push/pull streams, byte[] one-shots, sans-I/O header, async surface |
| 3 | #51 → HEAD (`e138704`) | 64 | 7,467 | docs/benchmarks, identity guards, armor lookahead + dearmor + seek, streaming grid, secret hygiene |

Checkpoint branches `review/p1` (at `170daf6`) and `review/p2` (at `d1c1236`) anchored the segments; both were deleted once the review was done. They can be recreated from those two SHAs.

### Review runs

| Part | Method | Result |
|------|--------|--------|
| 1 | cloud ultra | completed — 2 findings |
| 2 | cloud ultra (attempt 1) | **failed** — orchestrator lost all review agents mid-run; consumed a free slot |
| 2 | cloud ultra (attempt 2) | completed — 2 findings |
| 3 | local `/code-review`, xhigh effort | completed — 10 findings |

Free cloud runs were exhausted after part 2's retry, so part 3 ran locally at extra-high effort (10 finder angles + gap sweep) rather than as a paid cloud run.

---

## 2. A methodological caveat worth recording

**Reviewing at historical checkpoints produces stale findings.** Three of the four findings from parts 1 and 2 were already fixed at HEAD by later commits in the branch. Each was real at the commit it was reported against, and dead by the time it was reported.

This is intrinsic to the split, not a defect in the reviews. It means every finding from parts 1 and 2 required verification against HEAD before it could be acted on — which is what section 4 records. Part 3 was reviewed at HEAD and needs no such filter.

---

## 3. Findings — all fixed

Eleven findings survived at HEAD. **All are now fixed**; see `TODO.md` for the per-item record and section 7 for what changed. None was a security vulnerability. Ranked by consequence as reported:

### 3.1 Async `DecryptWriter` skips the empty-plaintext destination write
**`Age/Crypto/DecryptWriterStream.cs:376`** — *correctness, runtime-confirmed*

`Finish()` ends with `WriteOut(ReadOnlySpan<byte>.Empty)`, commented:

> Touch the destination even for empty plaintext — matters for lazy-creating writers that only materialize on first write.

On the async path `DisposeAsync` sets `_inAsyncWrite = true`, so `WriteOut` stages into `_pending` instead of writing, producing a zero-length `MemoryStream`. `DrainAsync` then returns early on `_pending.Length == 0` and the destination is never touched.

Observed:

```
sync  DecryptWriter, empty plaintext -> destination touched: True
async DecryptWriter, empty plaintext -> destination touched: False
sync  Decrypt(stream), empty plaintext -> True
async DecryptAsync(stream), empty plaintext -> True
```

`DecryptWriter` was the only cell of the streaming grid where sync and async disagreed. A destination that lazily creates a file on first write — the exact case the comment names — silently produced no file when an empty payload was decrypted asynchronously.

### 3.2 Sync `DecryptReader` leaves the file key unzeroed on the error path
**`Age/Age.cs:571`** — *secret hygiene, sync/async divergence*

`UnwrapHeaderFromReader` returns `fileKey`, `ReadPayloadNonce(reader)` runs, and `ZeroMemory(fileKey)` happened only after `HkdfDerive` succeeded. A file with a valid, MAC-verified header but a missing or short payload nonce makes `ReadPayloadNonce` throw; the catch zeroed `payloadKey` (still null) and disposed `binaryInput`, but never touched `fileKey`.

`DecryptReaderAsync` wrapped the identical sequence in `try/finally` with `ZeroMemory(fileKey)`. The two paths disagreed on the library's own standard. `UnwrapHeader` had the same shape: its `fileKey.Length != FileKeySize` throw and a failing `VerifyMac` both exited with the key unzeroed.

### 3.3 `Decrypt(byte[])` leaves plaintext in an unzeroed buffer
**`Age/Age.cs:248`** — *secret hygiene, asymmetry with `Encrypt`*

`Encrypt(ReadOnlySpan<byte>, ...)` copies plaintext into an owned buffer specifically so it can zero it in a `finally`, with a comment saying so. `Decrypt(ReadOnlySpan<byte>, ...)` wrote plaintext into `new MemoryStream()`, returned `output.ToArray()`, and disposed the stream — `MemoryStream.Dispose` does not clear its internal array, so a full second copy of the plaintext was abandoned to the GC on every byte[] decrypt.

### 3.4 `CryptoHelper.X25519Agree` contradicts its own sibling paths
**`Age/Crypto/CryptoHelper.cs:24`** — *consistency* — carried over from part 1

Three places performed an X25519 agreement, and they disagreed about whether BouncyCastle can be trusted to reject an all-zero shared secret:

| Location | Guard | Comment |
|---|---|---|
| `Age/Crypto/CryptoHelper.cs:24` | try/catch only | doc asserted BC "rejects by throwing" |
| `Age/Recipients/X25519Recipient.cs:71` | try/catch **+** `.All(b => b == 0)` | `// BouncyCastle may not reject all low-order points` |
| `Age/Crypto/XWing.cs:103` | try/catch **+** `.All(b => b == 0)` | `// low-order point that BC didn't reject` |

Not exploitable: BC 2.6.2 does throw on all-zero, and `Unwrap_LowOrderEphemeral_ThrowsFormatException` pins it. But the codebase asserted both "BC rejects this" and "BC may not reject this" about the same call, and the skeptical version was the one *not* applied on the attacker-controlled decrypt path.

### 3.5 Null element in a recipient/identity collection throws `NullReferenceException`
**`Age/Age.cs:698`** — *correctness, runtime-confirmed*

`Materialize` validated that the collection is non-null and non-empty but never checked its elements. `Age.Encrypt("x"u8, new IRecipient[] { recipient, null! })` threw `NullReferenceException` from inside `WrapWithLabels`. `Combine` carefully null-checks `first`; the collection overloads were the one shape where a caller mistake produced an unhelpful NRE from library internals.

### 3.6 Armor markers and geometry duplicated across three files
**`Age/Format/ArmorGeometry.cs:38`** — *reuse*

The begin/end markers appeared in `AsciiArmor`, `ArmorDecoder`, and `ArmorGeometry`. `ColumnsPerLine = 64` appeared in all three; the 48-byte line size appeared as `ArmorGeometry.BytesPerLine`, `ArmorDecoder.MaxDecodedPerLine`, and a local in `AsciiArmor.Armor`. `ArmorGeometry`'s entire correctness argument is that its arithmetic matches what the decoder accepts and the encoder emits — yet changing any one copy compiled cleanly while silently invalidating that argument.

Also: `ArmorGeometry.ProbeSize = 8192` and `AsciiArmor.ProbeSize = 1057` were the same identifier meaning two different things in one feature area. And `ReadFully`/`ReadFullyAsync` were a third near-copy of `AsciiArmor.ReadChunk*` and `SeekableDecryptStream.ReadFully*`, differing only in EOF handling.

### 3.7 `PeekableStream.Peek` discards unreplayed bytes if called twice
**`Age/Format/PeekableStream.cs:67`** — *latent*

`Retain` did `_peeked = buffer; _offset = 0; _length = length` — the previous buffer, including any portion not yet drained by `Read`, was dropped and those source bytes were gone. Not reachable at the time (`Detect`/`DetectAsync` peek exactly once on a fresh instance), but the XML doc advertised straightforward peek-then-read semantics with no mention that a second peek corrupts the stream.

### 3.8 `ArmorGeometry.TryResolve` blocks on an async `ValueTask`
**`Age/Format/ArmorGeometry.cs:64`** — *latent fragility*

`TryResolve` unwrapped the shared async core with `.GetAwaiter().GetResult()`. Safe only because every `await` inside completes synchronously. Calling `GetResult()` on a not-yet-completed `ValueTask` is undefined by contract, so adding any genuinely asynchronous step inside `Resolve` would have turned the sync armored-open path into a blocked thread or a throw, with nothing in the type flagging the constraint.

### 3.9 Armored header parsing allocates a `byte[1]` per header byte
**`Age/Format/DearmorStream.cs:66`** — *efficiency*

`HeaderReader` consumes the header via `stream.ReadByte()`. `Stream`'s base `ReadByte` allocates a fresh `byte[1]` per call, and `DearmorStream` overrode `Read(Span<byte>)` but not `ReadByte`. The binary path over `FileStream`/`MemoryStream` pays nothing (both override it). `MaxHeaderBytes` defaults to 16 MiB, so a large-but-accepted armored header became millions of one-byte allocations before anything was authenticated.

### 3.10 Parsing limits accept zero and negative values
**`Age/AgeDecryptOptions.cs:46`** — *robustness*

`MaxHeaderLineBytes`, `MaxHeaderBytes`, and `MaxArmorLineBytes` were unvalidated `init` properties. `new AgeDecryptOptions { MaxArmorLineBytes = 0 }` constructed fine and then threw `AgeFormatException("armor line exceeds 0 bytes")` on the first byte of any armored input — a complaint about the file rather than about the caller's configuration.

### 3.11 No `DecryptWriter` test decrypts an empty plaintext
**`Age.Tests/DecryptWriterTests.cs:304`** — *test coverage*

The only empty-related test was `EmptyFinalChunkAfterData_IsRejected`, which covers the malformed layout, not the legal empty file. The suite otherwise exercised the async path well — but with no empty-plaintext case, the contract in `DecryptWriterStream` was asserted nowhere, which is why 3.1 shipped.

---

## 4. Findings already resolved at HEAD

Recorded so they are not re-reported by a future review of the same checkpoints.

### 4.1 Truncation authentication bypass — **closed** (part 2, `normal`)

Reported against `d1c1236`: `SeekableDecryptStream` accepted any file whose encrypted payload was exactly 16 bytes, decrypting it to zero bytes with no exception — an attacker with no key could truncate any ciphertext to `header + nonce + 16 arbitrary bytes` and get a silent empty plaintext.

The guard the report pointed at is **still byte-identical** at HEAD: `lastChunkPlainSize == 0 && fullChunks > 0` still lets a 16-byte payload through `ComputePlaintextLength`. What closed the hole is upstream — PR #78 added `SeekableDecryptStream.Create`, which eagerly reads and decrypts the final chunk before returning, running Poly1305 verification with `isFinal=true`.

Verified by repro against HEAD:

```
empty file = 200 bytes, payload starts at 184
[NO THROW]                    A. empty file decrypts (control)  -> 0 bytes
[AgeAuthenticationException]  B. forged 16-byte payload (byte[] path)
[AgeAuthenticationException]  C. forged 16-byte payload (seekable MemoryStream)
[AgeAuthenticationException]  D. real ciphertext truncated to 16-byte payload
[AgeAuthenticationException]  E. same truncation, forward-only path
```

C and D are the exact attack from the report. Seekable and forward-only now agree.

### 4.2 Armored decrypt disposing the caller's stream — **closed** (part 2, `normal`)

Reported against `d1c1236`: the sync armored path wrapped the caller's stream in `using var dearmored`, and disposal cascaded down to the caller's `input`.

PRs #76/#77 replaced that block entirely with `AsciiArmor.Detect` + streaming dearmor, whose comment now states the caller's stream is never disposed. Verified: `Position = 349` after both `DecryptReader` and `Decrypt` on an armored source.

### 4.3 README showing a non-existent `Labels` property — **closed** (part 1, `nit`)

Reported against `170daf6`: the custom-recipient example showed a `Labels` property on `IRecipient`, which no longer exists. The docs rewrite replaced it; `README.md:377` now points at `IRecipientWithLabels` and its `WrapWithLabels` signature.

---

## 5. Investigated and cleared

Concerns raised during review that turned out to be non-issues. Recorded to prevent re-litigation.

- **`DearmorStream.Seek` past the body end** throws `AgeFormatException` internally rather than returning EOF — but it is unreachable through the public API. `SeekableDecryptStream` never seeks the dearmor stream past the body, and a caller seeking the returned stream only moves an integer. Verified: seek to 1000 on a 5-byte payload returns 0.
- **`ArmorDecoder.ValidateCanonicalPadding`** appears to index out of range on a line of `"="`, but `Convert.TryFromBase64Chars` rejects any non-multiple-of-4 line first, so `padCount` is always ≤ 2 on a line of ≥ 4 characters.
- **`Passphrase.Unwrap` checking stanza type before the disposed guard** is deliberate and pinned by `UnwrapOfAnotherStanzaType_StillReturnsNullAfterDispose`.
- **`PublicAPI.Shipped.txt` deletions** are correctly paired with `*REMOVED*` entries in `PublicAPI.Unshipped.txt`; the analyzer (`Microsoft.CodeAnalysis.PublicApiAnalyzers` 5.6.0) is wired up and reports zero warnings.
- **Conventions**: no repo-level `CLAUDE.md` exists, and none of the 30 commits in part 3's range carry a `Co-Authored-By: Claude` trailer.
- **Truncation and armor-truncation handling in `DecryptWriter`**: both correctly rejected. Byte-at-a-time and odd-sized writes round-trip correctly for binary, armored, and multi-chunk input.

---

## 6. Verification method

Findings were not accepted on reading alone. Two independent scratchpad console apps were built against `Age/Age.csproj` at HEAD and run:

1. **Staleness check** for parts 1 and 2 — the truncation attack (four variants), the stream-ownership check, and controls.
2. **Hypothesis suite** for part 3 — sync/async destination-touch comparison across all four decrypt entry points, null-element handling, byte-at-a-time and odd-sized write framing, truncation rejection, non-seekable armored input, and seek-past-end.

Findings 3.1 and 3.5 were observed runtime behaviour, not inference. The rest were code-inspection results where the defect is structural and a runtime probe would not add information.

**Repository state when reviewed:** 1,025 tests passing (143 `Age.TestKit` + 882 `Age.Tests`), zero build warnings including the PublicAPI analyzer.

---

## 7. Outcome

All eleven findings were fixed in this pass. Test count went from 1,025 to 1,034; the suite is green and the solution builds with zero warnings. No public API changed, so `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt` were untouched.

Two things surfaced during the fixes that the review itself had missed:

- **`XWing.Encaps` was a fourth X25519 agreement site with no guard at all.** Finding 3.4 named three; the encapsulation path had neither the try/catch nor the all-zero check, so a hostile `age1pq1…` recipient string carrying a low-order point would have escaped as a raw BouncyCastle `InvalidOperationException` rather than an `AgeFormatException`. Now routed through the same helper.
- **The armor constants were duplicated across five files, not three.** `ArmorStream.cs` and `ArmorWriterStream.cs` had their own copies of the 48-byte line size — six copies in total.

One deliberate behaviour change: `X25519Recipient.Wrap` now throws `AgeFormatException` where it previously threw `AgeException`. The new type is a subclass of the old, no test covered that path, and a hostile recipient string is a format problem — but it is a visible change for anyone catching the exact type, and belongs in the release notes.

### What the fixes looked like

| # | Fix |
|---|-----|
| 3.1 | `_pendingWrite` flag so `DrainAsync` keys off "did `WriteOut` run", not "is anything staged" |
| 3.2 | `try/finally` around the nonce read; `UnwrapHeader`'s two other exits zero the key too |
| 3.3 | `finally`-zeroed output buffer, covering the authentication-failure path |
| 3.4 | One agreement helper holding both guards; four call sites routed through it |
| 3.5 | Null-element scan in `Materialize`, reporting the index |
| 3.6 | New `ArmorFormat`; six read loops replaced with `ReadAtLeast`/`ReadExactly` |
| 3.7 | `Peek` grows and tops up rather than replacing the buffer |
| 3.8 | `ValueTask.IsCompleted` guard instead of a bare `GetResult()` |
| 3.9 | `ReadByte` override on `DearmorStream` |
| 3.10 | `RequirePositive` in each `init` accessor |
| 3.11 | Sync + async empty-plaintext tests, async confirmed red before the fix |

Nine tests were added: the two empty-plaintext ones, two null-element ones, a limits theory across all three options, two `PeekableStream` double-peek tests, and a wrap-side low-order rejection test.

---

## 8. Recommended action before tagging (as reported)

Grouped by the edit they imply, rather than by severity:

**Hygiene and consistency trio** — three small edits, same family, all in code that PR #85 was explicitly about:
- 3.4 route the three X25519 agreements through one helper with one all-zero policy
- 3.2 wrap the sync `DecryptReader` nonce read in `try/finally`, matching async
- 3.3 zero the intermediate plaintext buffer in `Decrypt(byte[])`

**Correctness** — one behavioural fix plus the test that should have caught it:
- 3.1 drain unconditionally, or write through on the async dispose path
- 3.11 add sync + async empty-plaintext tests for `DecryptWriter`

**Cleanup, non-blocking** — worth doing while the code is fresh:
- 3.6 consolidate armor constants and the three `ReadFully` variants
- 3.5 null-check collection elements in `Materialize`
- 3.10 validate `AgeDecryptOptions` limits at construction

**Latent, defer if time-pressed** — no current impact, real future traps:
- 3.7 document or fix `PeekableStream` double-peek
- 3.8 make `ArmorGeometry`'s sync path honestly synchronous
- 3.9 override `ReadByte` on `DearmorStream`

Nothing on this list blocked a tag on correctness or security grounds. The argument for fixing before the tag rather than after was that 3.1 changes observable behaviour, and 3.2/3.3/3.4 were consistency debts in exactly the area the release notes will claim was hardened.

---

## Appendix: reproducing the split

```bash
git branch review/p1 170daf6
git branch review/p2 d1c1236
```

Then, checking out each in turn: `/code-review ultra main` from `review/p1`, `/code-review ultra review/p1` from `review/p2`, `/code-review ultra review/p2` from `next-version`. Roughly 1,080 lines of part 3's 7,467 are vendored spec text in `docs/spec/`, so the real review surface there is smaller than the number suggests.

Cleanup: `git branch -D review/p1 review/p2`
