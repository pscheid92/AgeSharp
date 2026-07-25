# v0.3.0 review fixes — complete

All 11 standing findings from [docs/REVIEW_V0.3.0.md](docs/REVIEW_V0.3.0.md) are fixed.
Baseline 1,025 tests → **1,034 passing** (9 added), 0 build warnings.

## Hygiene and consistency

- [x] **3.4** — All X25519 agreements now route through `CryptoHelper.X25519Agree`, which holds
      the try/catch *and* the explicit all-zero check. Removed the contradicting comments in
      `X25519Recipient.Wrap` and `XWing.Decaps`.
      **Found while fixing:** `XWing.Encaps` was a fourth agreement site with *no* guard at all —
      a hostile `age1pq1…` recipient leaked a raw `InvalidOperationException`. Now covered.
      Exception type on the wrap path changed `AgeException` → `AgeFormatException` (a subclass);
      no test covered that path, and the new one pins the new behaviour.
- [x] **3.2** — `DecryptReader`'s nonce read is in `try/finally` zeroing `fileKey`, matching
      `DecryptReaderAsync`. `UnwrapHeader`'s bad-length and failed-MAC exits zero it too.
- [x] **3.3** — `Decrypt(byte[])` zeroes the intermediate `MemoryStream` buffer in a `finally`,
      so it clears on the authentication-failure path as well.

## Correctness

- [x] **3.1** — Added a `_pendingWrite` flag so `DrainAsync` keys off "did `WriteOut` run" rather
      than "is anything staged". "Nothing produced" and "empty produced on purpose" are now
      distinguishable, and the async path honours the empty write.
- [x] **3.11** — `EmptyPlaintext_TouchesTheDestination` + async counterpart. Confirmed the async
      one failed before 3.1 landed and passes after.

## Cleanup

- [x] **3.6a** — New `ArmorFormat` holds the markers and line geometry; `AsciiArmor`,
      `ArmorDecoder`, `ArmorGeometry`, `ArmorStream`, and `ArmorWriterStream` all use it.
      The review named three files; there were **five** — six copies of the 48-byte constant.
      `ArmorGeometry.ProbeSize` renamed `EdgeProbeSize` to end the name collision.
- [x] **3.6b** — Six hand-rolled read loops replaced with `ReadAtLeast`/`ReadExactly` and their
      async forms. `ArmorGeometry` relies on `EndOfStreamException` being an `IOException`, which
      `TryResolveCore` already catches.
- [x] **3.5** — `Materialize` scans for null elements and throws `ArgumentException` naming the
      index. Covers both the collection and `params` shapes, since the latter funnels through
      `Combine` into the same helper.
- [x] **3.10** — The three `AgeDecryptOptions` limits validate in their `init` accessors.

## Latent

- [x] **3.7** — `Peek`/`PeekAsync` grow and top up the buffer instead of replacing it, preserving
      the replay offset.
- [x] **3.8** — `TryResolve` guards on `ValueTask.IsCompleted` and throws rather than blocking.
- [x] **3.9** — `DearmorStream.ReadByte` override serving from the decoded buffer.

## Wrap-up

- [x] Full solution builds clean, 0 warnings (PublicAPI analyzer included — no public surface
      changed, so no `PublicAPI.*.txt` edits were needed)
- [x] 1,034 tests passing
- [x] Repro suite re-run: all four empty-plaintext paths now touch the destination; the null-element
      case reports `recipient at index 1 is null (Parameter 'recipients')`
- [x] `docs/REVIEW_V0.3.0.md` updated with outcomes
