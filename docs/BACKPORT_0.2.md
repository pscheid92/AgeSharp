# AgeSharp v0.2 backport survey

Target of this survey: **`main`** at `c295c10` (the v0.2 line, published as `0.2.0-preview.3`),
investigated in a clean worktree at
`/private/tmp/claude-501/-Users-pscheid-Projects-AgeSharp/f3dfa216-b5bc-4f2f-99e9-47910d60f1fd/scratchpad/main-wt`.
The `next-version` branch was used only as a source of already-written fixes to compare against; it
is **not** the target and several of its fixes are entangled with the v0.3 API redesign and are
explicitly excluded below.

Referee for every differential run: `age` v1.3.1 on PATH. Reference sources read locally:
`references/go-age/` (filippo.io/age) and `references/rust-age/` (rage), plus the vendored spec at
`docs/spec/age.md` / `docs/spec/age-plugin.md`.

---

## 1. Summary

**40 distinct defects** survived adversarial verification. Of those:

| | count |
|---|---|
| Reproduced empirically (transcript or differential run against `age`) | **32** |
| Confirmed by source reading only, not observed running | **8** |
| Security | 12 |
| Correctness | 12 |
| Interop | 5 |
| Hygiene | 11 |
| API-neutral as-is | 38 |
| Partially API-entangled (a neutral subset is described) | 2 |

**Headline risks, in order:**

1. **Arbitrary code execution.** `age-plugin-*` binaries are resolved through the process's
   *current working directory*, which the age-plugin spec explicitly forbids. Running an
   AgeSharp-based tool from inside an untrusted directory and using **any** plugin recipient
   executes an attacker-planted binary and hands it the raw file key. Reproduced on macOS.
   Both reference implementations refuse. (§S1)

2. **Silent acceptance of truncated ciphertext.** `AgeRandomAccess` derives the plaintext length
   from ciphertext *layout* and never authenticates the final chunk, so an attacker-truncated file
   is returned as a shorter plaintext with no error. `age` v1.3.1 and AgeSharp's *own* forward-only
   path both reject the same files. (§S2, §S3)

3. **main cannot read ~4.2% of valid armored age files — including its own output.** The armor
   decoder rejects any final body line that is 64 characters wide *and* carries base64 padding.
   That is exactly 2 of every 48 ciphertext lengths. An armored passphrase-encrypted identity file
   produced by `AgeKeygen.EncryptIdentityFile(..., armor: true)` is unreadable by AgeSharp about
   4% of the time; `age` reads all of them. (§C1)

4. **Cross-renter memory aliasing.** `DecryptStream`/`EncryptStream` return their pooled buffers to
   `ArrayPool<byte>.Shared` on *every* `Dispose`, and `Stream.Dispose()` is not idempotent. The
   idiomatic `using var s = DecryptReader(...); using var sr = new StreamReader(s);` shape hands one
   array to two unrelated renters, and produced spurious `chunk 0 authentication failed` errors on
   valid files in the repro. (§S4)

5. **Permanent, silent data loss through plugins.** A plugin returning more than one
   `recipient-stanza` has all but the last discarded; encryption reports success and the file is
   undecryptable by anything, including `age`. (§C4)

Nothing found is a break of the age cryptography itself. No all-zero X25519 shared secret is ever
fed into a KDF on main — BouncyCastle rejects it at all eight agreement sites even where AgeSharp's
own guard is absent. The zeroization findings are defence-in-depth (CWE-226 class): exploiting them
requires an independent local memory-disclosure primitive (core dump, swap, hibernation image,
debugger). They are reported as `security` because the project documents zeroization as an
invariant, not because any of them is remotely reachable.

---

## 2. Table of contents (by severity)

### Security (12)

| # | Defect | Reproduced |
|---|---|---|
| [S1](#s1) | Plugin binaries executed from the current working directory | yes |
| [S2](#s2) | `AgeRandomAccess` silently truncates when the final chunk is cut to its tag | yes |
| [S3](#s3) | `AgeRandomAccess` authenticates nothing when the computed length is 0 | yes |
| [S4](#s4) | Double `Dispose` returns pooled buffers twice — cross-renter aliasing | yes |
| [S5](#s5) | Disposed `MlKem768X25519Identity` / `X25519Identity` yield the all-zero-seed keypair | yes |
| [S6](#s6) | Client advertises `extension-labels` and then ignores the reply | yes |
| [S7](#s7) | The whole post-quantum path zeroes no secret at all | yes (partial) |
| [S8](#s8) | `CryptoHelper.HkdfDerive` leaves an uncleared heap copy of every input key | yes |
| [S9](#s9) | File key not zeroed on any error path in `AgeEncrypt` | yes |
| [S10](#s10) | `AgeKeygen` leaves the decrypted identity file (private keys) in memory | yes |
| [S11](#s11) | `Ed25519Converter` leaves the full SHA-512 expansion of the SSH private key | yes |
| [S12](#s12) | `Bech32` leaves the private key in 5-bit form and in a lowercased string | yes |

### Correctness (12)

| # | Defect | Reproduced |
|---|---|---|
| [C1](#c1) | Armor decoder rejects a padded 64-char final line — ~4.2% of files unreadable | yes |
| [C2](#c2) | The armor path disposes the **caller's** stream | yes |
| [C3](#c3) | Culture-sensitive `StartsWith` mis-frames header lines | yes |
| [C4](#c4) | Multi-stanza plugin response: all but the last silently discarded | yes |
| [C5](#c5) | identity-v1 sends a distinct FILE_INDEX per stanza | yes |
| [C6](#c6) | Plugin stderr is redirected but never drained — deadlock past 64 KiB | yes |
| [C7](#c7) | Raw `FormatException` / `ArgumentException` escape the plugin path | yes |
| [C8](#c8) | `SshEd25519Identity.Unwrap` has no low-order guard | yes |
| [C9](#c9) | `XWing.Encaps` leaks raw BCL exceptions out of `Encrypt` | yes |
| [C10](#c10) | `SshKeyParser` throws `ArgumentException` where `FormatException` is documented | yes |
| [C11](#c11) | Seek-from-End never verifies the final chunk (spec MUST) | yes |
| [C12](#c12) | `Read()` after `Dispose()` returns another renter's memory | yes |

### Interop (5)

| # | Defect | Reproduced |
|---|---|---|
| [I1](#i1) | Armored input is not detected on a non-seekable stream | yes |
| [I2](#i2) | `MlKem768X25519Recipient.Parse` accepts a structurally invalid ML-KEM key | yes |
| [I3](#i3) | scrypt work factor hard-capped at 20; Go's library default max is 22 | yes |
| [I4](#i4) | Plugin FILE_INDEX never validated; duplicate `file-key` silently replaces | yes |
| [I5](#i5) | A `confirm` with zero arguments is answered with a fabricated "yes" | yes |

### Hygiene (11)

| # | Defect | Reproduced |
|---|---|---|
| [H1](#h1) | `Header.ComputeMac` never zeroes the derived header MAC key | yes |
| [H2](#h2) | `ScryptRecipient` clears outside `finally`; passphrase held as a `string` | no |
| [H3](#h3) | Plugin wire path pushes secrets through unzeroable strings | no |
| [H4](#h4) | `X25519Identity.Unwrap` allocates the shared secret outside its `try` | no |
| [H5](#h5) | `AgeRandomAccess` does not zero a decrypted chunk on one error path | no |
| [H6](#h6) | Every mlkem stanza re-runs full ML-KEM keygen — ~7x pre-auth CPU vs `age` | yes |
| [H7](#h7) | Plugin `Dispose` stalls 5 s then abandons the process | yes |
| [H8](#h8) | `StreamEncryption`'s whole-stream methods buffer everything and are test-only | no |
| [H9](#h9) | Armor decoder accepts a bare CR as a line terminator | yes |
| [H10](#h10) | Armor decoder accepts leading whitespace on the BEGIN marker | yes |
| [H11](#h11) | No bound on leading whitespace before the BEGIN marker | yes |

---

## 3. Defects

<a id="s1"></a>
### S1 — Plugin binaries are executed from the current working directory

**Location** — `Age/Plugin/PluginConnection.cs:26` (`FileName = binaryName`), with the
`Win32Exception` → `AgePluginException` mapping at `:41`.

**What is wrong** — `ProcessStartInfo.FileName` is set to the bare name `age-plugin-<name>` with
`UseShellExecute = false` and no `WorkingDirectory`, and .NET's resolution then finds the binary in
the process's current working directory even when it is not on PATH. `docs/spec/age-plugin.md:60-63`
states verbatim: paths relative to the current working directory MUST NOT be searched, even on
platforms where that is the default.

**Reproduction** — reproduced on macOS 25.0.0 against a Release build of main.

```
$ mkdir /tmp/attacker && cp fake-plugin /tmp/attacker/age-plugin-cwd && chmod +x ...
$ which age-plugin-cwd            # not found — /tmp/attacker is NOT on PATH
$ cd /tmp/attacker && <probe>     # new PluginRecipient("age1cwd1qypqxpqujapgu").Wrap(fileKey)
STANZA type=cwdtype args=[] body=42424242
# planted binary's own log:
EXECUTED FROM CWD, argv=['/private/tmp/attacker/age-plugin-cwd', '--age-plugin=recipient-v1']
FILE KEY RECEIVED: 000102030405060708090a0b0c0d0e0f
```

Controls: from `/tmp/clean` → `Age.AgePluginException: plugin not found: age-plugin-cwd`
(`PluginConnection.cs:41`); from `/tmp/attacker/sub` (binary in the parent) → same exception. So
resolution is exactly CWD-relative, not inherited.

Referee, same setup: `age -r age1cwd1qypqxpqujapgu` from `/tmp/attacker` →
`"cwd" plugin not found: exec: "age-plugin-cwd": executable file not found in $PATH`.
go-age imports `golang.org/x/sys/execabs` for exactly this (`plugin/client.go:22`) and additionally
sets `cmd.Dir = os.TempDir()` (`plugin/client.go:463`). rust-age resolves via PATH only.

**Severity + who is affected** — **security (arbitrary code execution + file-key disclosure)**.
Any user of an AgeSharp-based tool who runs it with the working directory inside an untrusted tree
(unpacked archive, shared CI checkout, `~/Downloads`, a cloned repo) *and* encrypts or decrypts to
any plugin recipient/identity. Not Windows-only.

**API-neutral?** — Yes. `PluginConnection` is internal; only `ProcessStartInfo` construction changes.

**Fix shape** — Resolve `age-plugin-<name>` explicitly: split `PATH` on `Path.PathSeparator`, skip
empty and non-rooted entries (`Path.IsPathRooted`), probe each candidate (plus `PATHEXT` on Windows)
for an existing executable file, assign the resulting **absolute** path to `FileName`, and throw
`AgePluginException($"plugin not found: age-plugin-{name}")` when nothing matches. Also set
`startInfo.WorkingDirectory = Path.GetTempPath()`, matching go-age. **Not fixed on `next-version`
either** — its `PluginConnection.cs:26` is identical, so this must be written fresh and applied to
both branches.

**Confidence** — certain; reproduced independently twice.

---

<a id="s2"></a>
### S2 — `AgeRandomAccess` silently truncates when the final chunk is cut to exactly its tag

**Location** — `Age/AgeRandomAccess.cs:156` (`InitializeFromStream`), `:234-245`
(`ComputePlaintextLength`), `:90`/`:96` (`ReadAt` bound), with the guard that was written for this
case sitting unreachable at `:181-182`.

**What is wrong** — `PlaintextLength` is derived from ciphertext *layout* arithmetic only; nothing
is authenticated at construction. `DecryptChunkAt` is only ever reached for offsets strictly below
`PlaintextLength`, so a final chunk whose plaintext length is 0 is never decrypted and never
authenticated. Chunk layout alone cannot distinguish a truncated file from a shorter one.

**Reproduction** — encrypt N bytes with main, then drop the last `N mod 65536` ciphertext bytes so
the final chunk is exactly its 16-byte Poly1305 tag:

```
n=65537  cut=1   -> age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=65536  read=65536
n=65541  cut=5   -> age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=65536  read=65536
n=131073 cut=1   -> age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=131072 read=131072
n=131172 cut=100 -> age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=131072 read=131072
```

`age` v1.3.1 rejects all four. main's **own** forward-only path (`AgeEncrypt.Decrypt`) rejects all
four. `AgeRandomAccess` accepts all four and returns a plaintext short by 1 / 5 / 1 / 100 bytes with
no exception. The unreachability of the `:181` guard is provable: firing it needs
`chunkIndex > 0 && plaintext.Length == 0`, which implies `PlaintextLength == chunkIndex * 65536`,
contradicting the loop's `currentOffset < PlaintextLength`.

`docs/spec/age.md:161-162` requires decryption to signal an error if EOF is reached without
successfully decrypting a final chunk.

**Severity + who is affected** — **security**. Any library caller using `AgeRandomAccess` (the CLI
does not) on a file an attacker or a bad disk/transfer could have truncated.

**API-neutral?** — Yes. Entirely inside `AgeRandomAccess` internals; `AgePayloadException` is
already a documented constructor exception (`AgeRandomAccess.cs:44`).

**Fix shape** — In `InitializeFromStream`, after computing the layout, read and decrypt chunk
`totalChunks - 1` with `isFinal: true`, reject an empty final chunk when `totalChunks > 1`, and
derive `PlaintextLength` from that authenticated chunk. This is what `next-version` does in
`Age/Crypto/SeekableDecryptStream.cs` (`Create` → `FinalChunkLayout` → `CacheFinalChunk`). Delete
the now-false XML remark at `Age/AgeRandomAccess.cs:18-19`
("Truncation of the final chunk is only detectable when a read actually reaches it").
No existing test asserts the lenient behaviour (`Age.Tests/RandomAccessTests.cs` has no truncation
or tampering test at all).

**Confidence** — certain; reproduced independently by two investigators.

---

<a id="s3"></a>
### S3 — `AgeRandomAccess` authenticates nothing when the computed plaintext length is 0

**Location** — `Age/AgeRandomAccess.cs:90` (`ReadAt` early return), with `:153-156` (only
`totalEncrypted == 0` rejected) and `:241-242` (only `lastChunkPlainSize < 0` rejected).

**What is wrong** — When `ComputePlaintextLength` yields 0 — any payload of exactly 16 bytes, or a
payload chopped so only 16 bytes remain — `ReadAt` returns 0 immediately and no chunk is ever
decrypted. Construction rejects only `totalEncrypted == 0` and payloads under 16 bytes. The caller
cannot distinguish an authentic empty file from a forged or destroyed one.

**Reproduction**

```
valid empty file                       age_ok=True   fwd_ok=True                        seek_ok=True len=0
empty file, last tag byte flipped      age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=0 read=0
empty file, nonce last byte flipped    age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=0 read=0
n=65537,  payload chopped to 16 bytes  age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=0 read=0
n=131072, payload chopped to 16 bytes  age_ok=False  fwd_ok=False(AgePayloadException)  seek_ok=True len=0 read=0
```

`age` v1.3.1 and main's forward-only path reject every tampered case; `AgeRandomAccess` accepts all
of them.

**Severity + who is affected** — **security**. Same audience as S2. Listed separately from S2
because it is a distinct reachable input class: S2 needs `totalChunks > 1`, this needs
`totalChunks == 1`.

**API-neutral?** — Yes.

**Fix shape** — Subsumed by the S2 fix. Once the final chunk is authenticated at construction, the
`PlaintextLength == 0` case is covered because chunk 0 is decrypted as the final chunk.

**Confidence** — certain; reproduced.

---

<a id="s4"></a>
### S4 — Double `Dispose` returns pooled buffers twice, handing one array to two independent renters

**Location** — `Age/Crypto/DecryptStream.cs:148-161` and `Age/Crypto/EncryptStream.cs:152-164`
(neither `Dispose(bool)` has a `_disposed` guard; `ArrayPool.Return` at `:155-156` and `:159-160`
respectively). `Age/Format/ArmorStream.cs:119-125` is also unguarded and forwards to the inner
`EncryptStream`.

**What is wrong** — `System.IO.Stream.Dispose()` provides no idempotence guard, and `Stream.Close()`
is a documented alias for it, so calling both is legal caller code. Each call unconditionally
`Return`s both rented buffers, putting an array that is already on the pool's free list onto it
again; two subsequent unrelated `Rent` calls then receive the *same* array. The second `Dispose` also
runs `ZeroMemory` over the buffer, wiping whatever the new owner has since written.

**Reproduction** — reproduced deterministically 3/3 runs, from public API only:

```csharp
using var plaintext = AgeEncrypt.DecryptReader(new MemoryStream(ct), id);
using var sr = new StreamReader(plaintext);   // StreamReader.Dispose disposes the inner stream
_ = sr.ReadToEnd();                            // then the outer `using` disposes it again
// -> pool handed the same array to two renters: True
```

Direct demonstration of the wipe and the aliasing:

```
s = AgeEncrypt.DecryptReader(...); s.CopyTo(dst); s.Close(); s.Dispose();
var a = ArrayPool<byte>.Shared.Rent(65536);
var b = ArrayPool<byte>.Shared.Rent(65536);
// ReferenceEquals(a, b) == true
a.AsSpan(0,4).Fill(0xEE);   // renter A writes
// b[0] == 0xEE             // renter B observes renter A's bytes
```

Control: a single `Dispose` returns distinct arrays. The armored encrypt path
(`AgeEncrypt.EncryptReader(plaintext, armor: true, ...)`) reproduces the same aliasing through
`ArmorStream`. A downstream effect observed in the repro: with the pool corrupted, a subsequent
well-formed AgeSharp decrypt failed with a spurious
`AgePayloadException: chunk 0 authentication failed` — so this bug manifests as bogus authentication
errors on valid files.

`AgeRandomAccess.Dispose` (`:128`) and `X25519Identity.Dispose` (`:170`) both *do* have the guard,
so the two streams are the outlier.

**Severity + who is affected** — **security**. Cross-renter buffer aliasing between unrelated
`ArrayPool` consumers in the same process is a confidentiality and memory-integrity violation, not
merely missing defence in depth. One correction to how this has been described elsewhere:
`_plaintextBuffer` **is** zeroed on both `Dispose` passes, so age plaintext is not itself carried
out — the hazard is the generic aliasing.

**API-neutral?** — Yes. `DecryptStream`, `EncryptStream` and `ArmorStream` are all internal.

**Fix shape** — `private bool _disposed;` plus `if (disposing && !_disposed) { _disposed = true; … }`
in all three. Note this also fixes the current double-`_cipher.Dispose()` and double
`ciphertext.Dispose()` (when `ownsStream`). `next-version` fixed `DecryptStream`
(`Age/Crypto/DecryptStream.cs:15,192-207`) but **not** `EncryptStream`
(`Age/Crypto/EncryptStream.cs:221-233` there is still unguarded) — take just the guard, not the v0.3
restructuring or the `DisposeAsync` override, and apply the `EncryptStream` half to both branches.

**Confidence** — certain; reproduced independently by two investigators.

---

<a id="s5"></a>
### S5 — A disposed identity silently yields the all-zero-seed keypair instead of throwing

**Location** — `Age/Recipients/MlKem768X25519Identity.cs:27` (`Recipient`), `:64`
(`ToSecretString`), `:80` (`ToString`) — the `_disposed` guard exists only at `:91` (`Unwrap`).
Identical in `Age/Recipients/X25519Identity.cs:30`, `:76`, `:92`, guard only at `:103`.

**What is wrong** — `Dispose()` zeroes `_seed`, but `Recipient`, `ToSecretString()` and `ToString()`
have no guard and operate on the now-all-zero seed, returning a well-formed but publicly derivable
recipient / secret key. No error, no exception, no indication.

**Reproduction**

```
PQ after dispose:      pubA2 == pubB2? True    changed from real? True
PQ secret export:      AGE-SECRET-KEY-PQ-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQAE0WQE
X25519 after dispose:  pubA2 == pubB2? True    changed from real? True
X25519 pub:            age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p
X25519 sec:            AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3
Unwrap after dispose (both types): THREW ObjectDisposedException
```

Two distinct identities collapse to one publicly-derivable keypair. Anything encrypted to that
recipient is world-readable. `Unwrap` throwing correctly on the same instance makes the intent
unambiguous.

**Severity + who is affected** — **security**, but note the precondition honestly: it requires a
caller-side use-after-dispose bug. It is not attacker-reachable on its own. What makes it security
rather than a missing assertion is that the failure mode is *silent fail-open to a world-known key*.

**API-neutral?** — Yes. No `PublicAPI.*.txt` entry moves; only behaviour on an already-broken call
path changes.

**Fix shape** — `ObjectDisposedException.ThrowIf(_disposed, this);` at the top of the `Recipient`
getter and `ToSecretString()`; make `ToString()` return `"MlKem768X25519Identity(disposed)"` when
disposed rather than calling `Recipient`, so a debugger/logging `ToString` does not throw. Same three
lines in `X25519Identity`. `next-version` does exactly this
(`MlKem768X25519Identity.cs:33/46/120-124`, `X25519Identity.cs:35/52`); the guard is independent of
the `IIdentityWithRecipient` redesign.

**Confidence** — certain; reproduced independently by two investigators.

---

<a id="s6"></a>
### S6 — Client advertises `extension-labels` and then ignores the `labels` reply

**Location** — `Age/Recipients/PluginRecipient.cs:46` (the advertisement), `:24-25`
(`Label => null`), `:121-123` (default → `unsupported`). The label check that is thereby defeated is
`AgeEncrypt.BuildHeaderAndFileKey` at `Age/AgeEncrypt.cs:216-222`.

**What is wrong** — Sending `extension-labels` means, per `docs/spec/age-plugin.md:224-233`, that the
client will accept a `labels` command and MUST check that all recipient stanzas wrapping a given
file key have the exact same label set. `ReadWrapResponse` has no `labels` case: it falls through to
`unsupported`, and `PluginRecipient.Label` is hardcoded `null`, so the plugin's constraint is
silently discarded.

**Reproduction** — fake plugin `age-plugin-lbl` answering phase 2 with `-> labels postquantum`:

```
$ age -r age1lbl1qypqxtz4cd9 -r age1pf372jafrxxg78jsz7gj3s8z9rmscm8ydlus0httfjc6h02cad5sdpv6j4 -o out.age
age: error: incompatible recipients: can't mix post-quantum and classic recipients,
     or the file would be vulnerable to quantum computers          (exit 1)
plugin log: PLUGIN SENT: -> labels postquantum / client answered labels with: ok

$ <AgeSharp main, same two recipients>
exit 0, "ENCRYPTED"
plugin log: client answered labels with: unsupported
resulting header:
    -> lbl
    TEzkUPRe8NRRVzsgMTkWF53r
    -> X25519 B9MjYMIDFAmEhRBknJP5tsNoJJFh9+/EIYK/ShhlBHQ
```

The PQ-labelled plugin stanza and the classical X25519 stanza wrap the same file key — exactly the
failure labels exist to prevent.

**Severity + who is affected** — **security**, with the precondition stated plainly: the user must
themselves list both recipients. This is a guardrail bypass, not an attacker-triggered path. Anyone
using a labelling plugin (post-quantum, or a single-use "must not be combined" label).

**API-neutral?** — Yes.

**Fix shape** — Delete `conn.WriteStanza("extension-labels", [], []);` at `PluginRecipient.cs:46`.
A conforming plugin will then not send `labels`, and the client is honest about its capability.
This is exactly what `next-version` chose (`Age/Recipients/PluginRecipient.cs:44-45` carries the
comment explaining it). Full label support is **not** API-neutral on main — `IRecipient.Label` is a
single `string?` rather than a set — and must not be backported. `Age.Tests/PluginTests.cs:313`
asserts `-> extension-labels` is sent and must be updated.

**Confidence** — certain; reproduced.

**Follow-up: what the spec actually asks for, and why v0.2 cannot give it**

`references/age-plugin.md` is normative and unambiguous that a label is a *set* per recipient:

- `:307` — "The order of labels in the command is irrelevant. Clients MUST treat them as an
  unordered set."
- `:227` — "Clients MUST check that all recipient stanzas wrapping a given file key have the exact
  same label set. Clients MUST NOT permit partial overlapping sets."
- `:305` — "Plugins MUST NOT send duplicate labels", so sorted-list equality is set equality for any
  conforming plugin. `references/go-age/age.go:130` relies on exactly that (`sort.Strings` then
  `slices.Equal`).
- `:291-304` names three idioms: a *common public* label (`postquantum`), a *common private* label
  (plugins from one vendor that may only combine with each other), and a *random* label (force the
  stanza to be used alone).

Our `IRecipient.Label` is `string?`, so it represents the empty set and singletons only. Of the
three idioms, two survive: `postquantum` is a singleton, and the random-label idiom works because
`firstLabel` is read once and cached, so a lone recipient passes and any pairing fails. What cannot
be represented is a set of size >= 2 — a vendor plugin wanting `{postquantum, acme-internal}` has to
drop one, and dropping either silently loosens a constraint the plugin was relying on.

There is a second, structural reason the type alone is not the whole gap. `Label` is a property read
*before* any wrapping (`AgeEncrypt.BuildHeader`), whereas a plugin can only declare its labels
partway through the recipient-v1 conversation — `references/go-age/plugin/client.go:141` takes them
from the wrap exchange, which is why Go's interface is
`WrapWithLabels(fileKey) (stanzas, labels, err)`. A property that must answer before the plugin
process starts cannot carry plugin labels whatever its type is.

Both are why S6's fix is to stop advertising `extension-labels` rather than to half-implement it.

**Related divergence: scrypt's implicit label set (not a defect)**

`references/age-plugin.md:232-233` — "The `scrypt` recipient stanza has an implicit label set
containing a single random label. In other words, it can't be combined with any other stanza."
`ScryptRecipient` declares no label at all, so by the spec's model it reports the *empty* set, the
same as x25519 (`:231`), and the label check alone would let `scrypt + x25519` through. The rule is
enforced instead by the explicit structural check in `BuildHeader` that rejects a scrypt stanza
alongside any other. Same outcome by a different mechanism, and arguably the stronger one: it runs
*after* `Wrap` and keys off the emitted stanza type, so a custom recipient that emits a scrypt
stanza is caught too, which a label on `ScryptRecipient` would not catch. Recorded so the divergence
is deliberate rather than discovered later.

**v0.3 shape** — move labels onto the wrap result rather than a property, and widen to a set:
`WrapResult Wrap(ReadOnlySpan<byte> fileKey)` carrying `IReadOnlyList<Stanza>` plus
`IReadOnlySet<string> Labels`. That subsumes S6, the `IMultiStanzaRecipient` side-interface added for
C4, and this scrypt special case in one change — scrypt then genuinely returns a random singleton,
as the spec describes.

---

<a id="s7"></a>
### S7 — The whole post-quantum path zeroes no secret at all

**Location**
- `Age/Crypto/XWing.cs` — `grep -c ZeroMemory` returns **0** for the entire file.
  `seedPq` `:127` (64 bytes = the ML-KEM-768 private seed `(d,z)`), `seedT` `:130` (32 bytes = the
  X25519 private scalar), `ssM`/`ssX` `:49`/`:55` (Encaps) and `:84`/`:88` (Decaps), the combined
  secret from `CombineSharedSecret` `:108-120`. `ExpandSeed` also returns `seedPQ` in a tuple that
  both call sites (`:25`, `:76`) discard with `_`.
- `Age/Crypto/HpkeHelper.cs` — `grep -c ZeroMemory` returns **0**. `secret` (HPKE PRK) `:49`,
  `key` (the ChaCha20-Poly1305 key that unwraps the file key) `:50`, `baseNonce` `:51`; `ss`, `key`
  and `nonce` in `SealBase` `:21-27` and `OpenBase` `:29-34`; `labeledIkm` `:60` in `LabeledExtract`,
  which holds a raw copy of the X-Wing shared secret.
- `Age/Recipients/MlKem768X25519Recipient.cs:56` —
  `HpkeHelper.SealBase(_publicKey, AgeProtocol.MlKemHpkeInfo, fileKey.ToArray())`: an uncleared heap
  copy of the **file key itself**, created inline as an argument so no reference exists to clear.

**What is wrong** — `CLAUDE.md`'s own table promises "X-Wing components, HPKE PRK, seeds → cleared by
the deriving method itself" and "file key → never reaches the GC heap". On main that is documentation
of intent, not of behaviour. `ExpandSeed` runs on every `Encaps`, every `Decaps`, **and** every
`XWing.GeneratePublicKey` — which `MlKem768X25519Identity.Recipient` calls, which `ToString()` calls.
So merely logging a PQ identity re-derives and abandons its full ML-KEM private seed, and
`MlKem768X25519Identity.Dispose` does not actually erase the private key it promises to.

**Reproduction** — heap-residue probe (Release; run the operation, drop all references, run four
**non-compacting** blocking gen2 collections, then allocate ~520 MB via
`GC.AllocateUninitializedArray<byte>(64 KiB)` and search the recycled pages; needles pinned alive so
they are never themselves swept; two controls in every run).

```
== controls (validate the technique) ==
  a value that only ever existed in a live array   residue=False (expect False)  as expected
  an array deliberately dropped without clearing   residue=True  (expect True)   as expected
== XWing / HpkeHelper ==
  64-byte ML-KEM-768 PRIVATE SEED, after Decrypt   residue=True  (expect True)   as expected
  HPKE PRK (secret) after encrypt+decrypt          residue=True
  HPKE AEAD key (unwraps the file key)             residue=True
  PQ Wrap: fileKey.ToArray() heap copy             residue=True
  32-byte X-Wing shared secret, 200 PQ decrypts    11 copies vs zeroed control 1 (0 at ITER=0)
```

**Caveats stated plainly.** (a) The X-Wing shared-secret residue does not accumulate (11 copies at
both 200 and 800 iterations) because the PQ path's large allocations churn the heap and overwrite
older copies — a weaker signal than the file-key case, but not a refutation. (b) Attribution is
imperfect: BouncyCastle's `MLKemPrivateKeyParameters.FromSeed` retains the seed internally, and the
BCL/BouncyCastle AEAD retains the key, so clearing AgeSharp's own arrays reduces but may not
eliminate residue. What is *proved* is that these secrets survive the operation on the reclaimable
heap; that AgeSharp's own arrays are uncleared is certain by inspection.
(c) Exploitation requires local memory disclosure (core dump, swap, hibernation image, debugger) —
this is defence-in-depth, not a remote attack. What lifts it above hygiene is that `seedPq` is
`(d,z)` for ML-KEM-768 `KeyGen_internal` and `seedT` is the X25519 scalar: either is
identity-equivalent, so residency is full key compromise rather than a transient secret.

Contrast with main's own classical path: `X25519Recipient.cs:84` passes the file key span straight
into `ChaChaEncrypt` with no `ToArray`, and `:89-93` zeroes `wrapKey` and `sharedSecret` in a
`finally`.

**Severity + who is affected** — **security (defence in depth)**. Every user of the `age1pq1` /
`mlkem768x25519` recipient type.

**API-neutral?** — Yes. `XWing` and `HpkeHelper` are `internal static class`;
`MlKem768X25519Recipient.Wrap`'s public `Stanza Wrap(ReadOnlySpan<byte>)` signature is untouched.

**Fix shape**
1. `XWing.ExpandSeed`: wrap the body in `try/finally` and `ZeroMemory(seedPq)` + `ZeroMemory(seedT)`.
   Verified empirically that this is safe — BouncyCastle copies what it needs
   (`MLKem FromSeed: pk stable after zeroing seed? True`;
   `X25519 ctor: pk stable after zeroing scalar? True`). Drop the discarded `seedPQ` tuple element
   while you are there.
2. Give `CombineSharedSecret` ownership of `ssM`/`ssX` and clear both in a `finally`.
3. `HpkeHelper.KeyScheduleBase`: clear `secret` and the incoming `sharedSecret` in a `finally`;
   `SealBase`/`OpenBase` clear `key` and `nonce`; `LabeledExtract` clears `labeledIkm`.
4. Change `HpkeHelper.SealBase`'s third parameter from `byte[]` to `ReadOnlySpan<byte>` and drop the
   `.ToArray()` at `MlKem768X25519Recipient.cs:56`.

Items 1-3 exist on `next-version` (`Age/Crypto/XWing.cs:99-100,141-142`;
`Age/Crypto/HpkeHelper.cs:33,48,76-77`) and lift almost verbatim. Item 4 is entangled there with the
span-based `IRecipient.Wrap` redesign; the `ReadOnlySpan` parameter on the internal `SealBase` is the
neutral substitute. Do **not** import `next-version`'s caller-filled-span restructuring from
`30f38d1`.

**Confidence** — certain on the source facts; reproduced for the seed, PRK, AEAD key, file-key copy
and shared secret.

---

<a id="s8"></a>
### S8 — `CryptoHelper.HkdfDerive` leaves an uncleared heap copy of every input key

**Location** — `Age/Crypto/CryptoHelper.cs:23`:

```csharp
hkdf.Init(new HkdfParameters(ikm.ToArray(), salt.ToArray(), Encoding.ASCII.GetBytes(info)));
```

`grep -c ZeroMemory Age/Crypto/CryptoHelper.cs` → 0.

**What is wrong** — `ikm.ToArray()` allocates a GC-heap copy of the input keying material that no
caller can see or clear. Callers deliberately pass `ReadOnlySpan<byte>` so the secret need not be
heap-resident, and then dutifully zero their own buffers — the `ToArray` silently undoes that.
`X25519Identity.Unwrap` zeroes its `sharedSecret` in a `finally` at `:160-164` and it makes no
difference.

All 13 call sites enumerated; 11 pass a secret:

| ikm | sites |
|---|---|
| file key | `AgeEncrypt.cs:92`, `:130`, `:178`, `:201`; `AgeRandomAccess.cs:149`; `Format/Header.cs:90` |
| X25519 / ssh shared secret | `X25519Identity.cs:150`, `X25519Recipient.cs:78`, `SshEd25519Identity.cs:120`, `SshEd25519Recipient.cs:75` |
| empty (harmless) | `SshEd25519Recipient.cs:48`, `SshEd25519Identity.cs:106` |

The `salt` is never secret (payload nonce, ssh wire bytes, `ephPub‖pubkey`) and `info` is a literal,
so only the `ikm` copy needs clearing.

**Reproduction** — differential heap-residue measurement, two independent runs:

```
Run A (spy IIdentity capturing the file key, 301 decrypts):
  FILE KEY residual copies, unmodified main : 1800   (zeroed 16-byte control: 1)
  FILE KEY residual copies, one-line fix    : 1200   (control: 1)
  -> ~600 copies over ~300 decrypts = 2 per decrypt = the two HkdfDerive calls per decrypt

Run B (needle = 32-byte X25519 shared secret, recomputed independently with BouncyCastle):
  16-byte FILE KEY, after AgeEncrypt.Encrypt      residue=True (expect True)
  32-byte X25519 SHARED SECRET, after Decrypt     residue=True (expect True)
  controls behaved correctly in the same run
```

**Caveat, and it matters for the changelog:** the one-line fix removes only about one third of the
residue (1800 → 1200). BouncyCastle's `HMac`/`Sha256Digest` block buffer retains any IKM ≤ 64 bytes
internally, which the fix cannot reach. Do **not** describe this fix as eliminating the residue.

**Severity + who is affected** — **security (defence in depth)**. Every encrypt and every decrypt,
every recipient type. Not remotely exploitable.

**API-neutral?** — Yes, in the form below.

**Fix shape**

```csharp
var ikmCopy = ikm.ToArray();
try { /* existing body, using ikmCopy */ }
finally { CryptographicOperations.ZeroMemory(ikmCopy); }
```

`CryptoHelper` is `internal static`; keep main's `byte[] HkdfDerive(ReadOnlySpan<byte>,
ReadOnlySpan<byte>, string, int)` signature. `next-version`'s `30f38d1` **also** flipped the method
to fill a caller-supplied `Span<byte>`, cascading into 22 call sites — that half is v0.3 API redesign
and must be dropped from the backport.

**Confidence** — certain; reproduced, with the fix's effect measured differentially.

---

<a id="s9"></a>
### S9 — The file key is not zeroed on any error path in `AgeEncrypt`

**Location** — five reachable throw sites:

| # | site | trigger |
|---|---|---|
| 1 | `Age/AgeEncrypt.cs:199-210` (`DecryptReader`) | `ReadPayloadNonce` throws on a file truncated inside the nonce; `ZeroMemory` at `:202` is skipped and the `catch` at `:206-210` only disposes the dearmor stream |
| 2 | `Age/AgeEncrypt.cs:275` (`UnwrapHeaderFromReader`) | `header.VerifyMac(fileKey)` throws `AgeHmacException` on a corrupted/tampered header, after the genuine key is unwrapped, with no `finally` anywhere |
| 3 | `Age/AgeEncrypt.cs:272-273` (same method) | a non-16-byte return from a custom or plugin identity |
| 4 | `Age/AgeEncrypt.cs:230` (`BuildHeaderAndFileKey`) | `recipient.Wrap(fileKey)` throws — an `AgePluginException` (plugin missing, user declines a touch prompt) is entirely routine |
| 5 | `Age/AgeEncrypt.cs:170-181` (`EncryptReader`) | anything in `header.WriteTo` / `HkdfDerive` before the `ZeroMemory` at `:179` |

Sites 2, 3 and 4 also reach `EncryptDetached` and `DecryptDetached`, because those methods call
`BuildHeaderAndFileKey` (`:85`) and `UnwrapFileKey` (`:112`) **outside** their otherwise-correct
`try` blocks.

**What is wrong** — Per the project's own rule, a value returned across the API is cleared by
whoever owns it next — the facade — and the facade does clear it on the success path. These are pure
error-path omissions. Sites 1, 2 and 3 are triggered by attacker-supplied ciphertext.

**Reproduction** — differential probe with a spy identity that forwards to the real
`X25519Identity` and retains the array it returned; stable across repeated runs.

```
success: whole file decrypts                   residue=False (expect False)  as expected
threw AgeHeaderException: expected 16-byte payload nonce, got 4 bytes
error: payload nonce truncated                 residue=True  (expect True)   as expected
threw AgeHmacException: header MAC verification failed
error: header MAC verification fails           residue=True  (expect True)   as expected
```

Direct observation of the retained array on the MAC-failure path: `4B9531B9ED62DC57E6AE4762F093C0A9`
(the genuine file key) instead of 16 zero bytes; the success-path control observed all zeros.
On the truncated-nonce path: `4B9531B9ED62DC57E6AE4762F093C0A9`.

Site 4 reproduced separately with a NoGC-region pointer probe and a throwing custom `IRecipient`:
the live file key leaked from **both** `EncryptReader` (`FE5A4774C4264AAC67A8643E3522B60C`) and
`EncryptDetached` (`A923DD2DD1915D63F610E0B3826DE318`); the success-path control read all zeros. A
recipient returning a `null` `Stanza` (`NullReferenceException` at `header.WriteTo`) also leaked
(`0D6203693EE17BB589A3FECC4B6F5B3C`). Note the author *did* zero on the one guarded path — the
scrypt-mixing check at `:235-239` — and that path is verifiably clean, so this is partial awareness
rather than a blind spot.

Sibling control: `AgeRandomAccess.InitializeFromStream` (`Age/AgeRandomAccess.cs:146-162`) has the
correct `try/finally` and passes the same probe, so the two paths already disagree with each other.

**Severity + who is affected** — **security (defence in depth)**. Sites 1-3 are reachable purely
from attacker-supplied truncated or tampered ciphertext with no custom types involved.

**API-neutral?** — Yes; pure control flow inside existing method bodies.

**Fix shape** — Two different shapes, and getting them the wrong way round is the easy mistake:

- `DecryptReader` and `EncryptReader` do **not** return the key → `try/finally` is correct. In
  `DecryptReader`, `fileKey` is declared *inside* the `try` at `:199`, so the declaration must be
  hoisted (`byte[]? fileKey = null;`) before a `finally` can see it.
- `UnwrapHeaderFromReader` and `BuildHeaderAndFileKey` **do** return the key → these must be
  `catch { ZeroMemory(fileKey); throw; }`, not `finally`.
- Put the guard **inside** `BuildHeaderAndFileKey` (covering the `Wrap` loop), not only in
  `EncryptReader`'s body, otherwise both encrypt entry points stay leaky.

`next-version`'s equivalents are `Age/Age.cs:281-301` and `Age/Age.Header.cs:79,128`, but those files
are entangled with the v0.3 facade rewrite — apply the local insertions above instead.

**Confidence** — certain; reproduced independently by three investigators.

---

<a id="s10"></a>
### S10 — `AgeKeygen` leaves the decrypted identity file — private keys in the clear — in memory

**Location** — `Age/AgeKeygen.cs:140-148` (`DecryptIdentityFile`; copies originate at `:143`
`MemoryStream`, `:146` `ToArray()` + `GetString`) and `:153-161` (`EncryptIdentityFile`; `:155`
`GetBytes`). `grep -c ZeroMemory Age/AgeKeygen.cs` → 0.

**What is wrong** — `Encoding.UTF8.GetString(output.ToArray())` produces **three** uncleared copies
of the file's `AGE-SECRET-KEY-1…` / `AGE-SECRET-KEY-PQ-1…` lines: the `MemoryStream`'s internal
buffer (`Dispose` does not clear it), the separate `ToArray()` array, and an immutable `string` that
cannot be zeroed at all. `ParseIdentityFile` then splits it, producing one more per-line string.
`EncryptIdentityFile` is the mirror: `Encoding.UTF8.GetBytes(identityFileText)` is never cleared.

**Reproduction** — round-trip an identity file containing a real `AGE-SECRET-KEY-1…` line through
`EncryptIdentityFile` / `DecryptIdentityFile` (work factor 4), then sweep; the secret string is
pinned alive so it is excluded from the sweep.

```
== AgeKeygen.DecryptIdentityFile / EncryptIdentityFile ==
  (round-trip recovered 1 identity)
  AGE-SECRET-KEY-1… as UTF-8 (decrypted file buffer)  residue=True (expect True)  as expected
  AGE-SECRET-KEY-1… as UTF-16 (the string itself)     residue=True (expect True)  as expected
```

Also confirmed that clearing `output.GetBuffer()` and `plaintextBytes` alone is **not** sufficient —
the string copies remain.

**Severity + who is affected** — **security (defence in depth)**. Anyone using passphrase-protected
identity files.

**API-neutral?** — The array clearing is fully neutral (both methods are public but only their
bodies change). The `string` copies are **irreducible on main** — `ParseIdentityFile(string,
IPluginCallbacks)` is in `PublicAPI.Shipped.txt:112` and changing it is an API break. `next-version`
accepts the same limitation and documents it. Backport only the array clearing and document the
residual.

**Fix shape** — `DecryptIdentityFile`: switch to
`Encoding.UTF8.GetString(output.GetBuffer(), 0, (int)output.Length)` (avoids the `ToArray` copy) and
add `finally { CryptographicOperations.ZeroMemory(output.GetBuffer()); }`. `EncryptIdentityFile`:
`try/finally` with `ZeroMemory(plaintextBytes)`. Shape matches `next-version`
`Age/Recipients/EncryptedIdentityFile.cs:108-119`.

**Two caveats that make the fix more partial than it looks.** (a) `MemoryStream` reallocates its
backing array as it grows, so zeroing `GetBuffer()` only reaches the *final* buffer — every
intermediate growth generation is still abandoned. Pre-size the stream
(`new MemoryStream(capacity)`) so it never reallocates. (b) `new MemoryStream()` does set
`publiclyVisible = true` so `GetBuffer()` is legal, but its `.Length` is the **capacity**, not the
stream length — zero the whole capacity.

**Confidence** — certain by inspection; reproduced.

---

<a id="s11"></a>
### S11 — `Ed25519Converter` leaves the full SHA-512 expansion of the SSH private key on the heap

**Location** — `Age/Crypto/Ed25519Converter.cs:58-65` (`hash`, dropped after `:64`; the file
contains no zeroing) and `Age/Recipients/SshEd25519Identity.cs:48`
(`ed25519Private.GetEncoded()` passed inline).

**What is wrong** — `PrivateKeyToX25519` computes `hash = SHA-512(ed25519Seed)` into a 64-byte array,
copies the first 32 bytes out as the X25519 private key, and drops `hash` uncleared. Bytes 0-32 are
the X25519 private key that `SshEd25519Identity.Dispose` is careful to zero; bytes 32-64 are the
Ed25519 nonce prefix, also private key material. So `Dispose` zeroes one copy while a complete
second copy plus the signing nonce sits in freed memory. Separately, `GetEncoded()` returns a fresh
BouncyCastle copy of the raw Ed25519 seed, also never cleared, from the moment an `ssh-ed25519`
identity is parsed.

**Reproduction** — real key from `ssh-keygen -t ed25519`, parsed, encrypt+decrypt round trip,
identity disposed, then swept with all hook copies pinned:

```
SHA-512(ed25519 seed), full 64 bytes        residue=True
bytes 32..64 (Ed25519 nonce prefix) alone   residue=True
```

The second needle proves the signing-nonce half survives too, not just the part that overlaps the
X25519 key. Only one capture occurred (`Parse` calls the converter once), so the hook is not its own
confounder.

**Severity + who is affected** — **security (defence in depth)**. Every user of `ssh-ed25519`
identities.

**API-neutral?** — Yes; `Ed25519Converter` is internal and the `Parse` change is method-local.

**Fix shape** — `try/finally` around `PrivateKeyToX25519`'s body with `ZeroMemory(hash)`; in
`SshEd25519Identity.Parse`, hoist `ed25519Private.GetEncoded()` into a local and zero it in a
`finally` after the conversion. **Not fixed on `next-version`** —
`Age/Crypto/Ed25519Converter.cs:47-60` there is byte-identical in this respect, so this must be
written fresh and applied to both branches.

**Confidence** — certain; reproduced.

---

<a id="s12"></a>
### S12 — `Bech32` leaves the private key in 5-bit form, in a `List<byte>` backing array, and in a lowercased string

**Location** — `Age/Crypto/Bech32.cs`. `grep -c ZeroMemory` → 0. Decode side: `data5` `:134`,
`data5NoCheck` `:148`, `ConvertBits` `:156-192` (its `List<byte>` backing array plus every discarded
generation from capacity doubling), `ret.ToArray()`, `bech.ToLowerInvariant()` `:130`. Encode side:
`data5` `:86`, `values` in `CreateChecksum` `:67`, the `result` char[] `:89`.

**What is wrong** — `X25519Identity.Parse` (`:66-68`) and `MlKem768X25519Identity.Parse` (`:54-56`)
are careful to `ZeroMemory` the `byte[]` that `Bech32.Decode` returns — and `Decode` itself leaves
several uncleared representations of the same secret behind. `data5` is a trivially-invertible 5-bit
representation of the raw `AGE-SECRET-KEY` / `AGE-SECRET-KEY-PQ` payload. `ConvertBits` uses
`new List<byte>()` with no capacity, so the backing array is reallocated as it grows and every
superseded generation is dropped uncleared — the copy count is non-deterministic. `Bech32.Encode`
has the mirror problem, so `X25519Identity.ToSecretString()` leaks on the way out despite zeroing
`rawCopy`.

**Reproduction** — generated an `X25519Identity`, round-tripped it through
`ToSecretString()` / `Parse()`, pinned all hook copies, swept:

```
data5 (5-bit form of AGE-SECRET-KEY-1 payload)   residue=True   (zeroed control: residue=False)
```

Single capture, so no self-confounding.

**Severity + who is affected** — **security (defence in depth)**. Anyone parsing or exporting a
secret key string. The exposure is the same class as S10 and S11: an existing, deliberate protection
is defeated by an intermediate the protecting code cannot see.

**API-neutral?** — Yes; `Bech32` is `internal static`.

**Fix shape** — Rewrite `Decode`/`Encode` to work in caller-visible buffers cleared in a `finally`:
replace `ConvertBits`'s `List<byte>` with a pre-sized array (the output length is computable), and
add `try/finally` clearing `data5`, `data5NoCheck` and the `ConvertBits` scratch. The lowercased
string is irreducible without changing `Decode`'s `string` parameter; leave it and document it.
**Not fixed on `next-version`** — its `Bech32.cs` has zero `ZeroMemory` calls too, so this must be
written fresh.

**Confidence** — certain by inspection; the `data5` residue reproduced.

---

<a id="c1"></a>
### C1 — Armor decoder rejects a final 64-char line carrying base64 padding

**Location** — `Age/Format/DearmorStream.cs:103-104` (the throw), `:107-108` (padding validation
gated on width), `:143-144` (final-line tracking gated on width).

**What is wrong**

```csharp
if (line.Length == ColumnsPerLine && bytesWritten != MaxDecodedPerLine)
    throw new AgeArmorException("non-canonical base64 in armor");
```

The premise — "a 64-character line must decode to a full 48 bytes" — is false. A final chunk of
**46** bytes base64-encodes to 15 full groups (60 chars) plus `XX==` = exactly 64 characters;
**47** bytes encodes to 64 characters ending in a single `=`. Both are canonical PEM/age armor. Both
reference implementations key off the **decoded** length: go-age `armor.go:156` uses
`if n < format.BytesPerLine`; rust-age `primitives/armor.rs:873` accepts
`(false, ARMORED_COLUMNS_PER_LINE) => ()` unconditionally and lets base64 decode it. main rejects
files that **both** references accept.

The same false premise breaks the two neighbouring rules — `ValidateCanonicalPadding` is only called
for lines shorter than 64, and `_lastLineWasShort` is only set for lines shorter than 64. (Both are
vacuous today because the throw fires first; they become live once the throw is removed, which is why
the three edits must land together.)

**Reproduction** — all four campaigns reproduced independently twice on a clean copy of main.

*(1) Size sweep 0..200 across the mod-48 cycle.*

```
for n in $(seq 0 200); do
  head -c $n /dev/urandom > pt.bin
  age -a -r $PUB -o ct.age pt.bin
  Age.Cli -d -i key.txt -o out.bin ct.age
done
```

8 of 201 fail, all with `age: non-canonical base64 in armor`, at plaintext sizes
**38, 39, 86, 87, 134, 135, 182, 183** — exactly the sizes where the *binary ciphertext* length
≡ 46 or 47 (mod 48). Verified: n=38 → 238 bytes (mod 48 = 46), n=39 → 239 (47), n=37 → 237 (45,
passes), n=40 → 240 (0, passes). The offending line, printed:
`r0Racp5TosWbbCN9E97T31TXN7VEA+b4LgHky4fcmjpzL619tNzt6fDSsG4ZTQ==` — 64 characters.

*(2) Across a chunk boundary,* `seq 65400 65700`: 14 of 301 fail (65414/65415, 65462/65463,
65510/65511, 65542/65543, 65590/65591, 65638/65639, 65686/65687). The residue shifts by the extra
16-byte tag of the second chunk, confirming it tracks *ciphertext* length.

*(3) Not X25519-specific.* With two `-r` recipients (header 54 bytes longer) the failing plaintext
sizes shift to 36, 37, 84, 85.

*(4) main cannot round-trip its own armor.* `Age.Cli -e -a` then `Age.Cli -d` fails at exactly the
same 8 sizes in 0..200, while `age -d` accepts **all 201** of main's armored outputs. The encoder is
correct; only the decoder is wrong.

*(5) Worst concrete case — an encrypted key file that cannot be read back.*
`AgeKeygen.EncryptIdentityFile(text, pass, armor: true)` → `AgeKeygen.DecryptIdentityFile(blob,
pass)`, sweeping a 0..95-character comment to walk the residue: **4 of 96 fail** (comment pad 27, 28,
75, 76) with `AgeArmorException: non-canonical base64 in armor`. A v0.2 user's armored encrypted
identity file is unreadable by v0.2 roughly 4.2% of the time. `age` reads it fine.

**Failure rate: 2 of every 48 ciphertext lengths = 4.17% of arbitrary files.**

*Fix verified end to end.* Applied the patch below to a copy of main, rebuilt with
`-p:TreatWarningsAsErrors=true` (0 warnings), re-ran sweeps 0..200 and 65400..65700 → 0 failures and
0 content mismatches; identity-file sweep → 0 failures; full suite green (431 `Age.Tests` + 143 CCTV
vectors). No existing test asserted the old behaviour. Strictness preserved: a 64-char padded line
mutated to have non-zero trailing bits is still rejected, and a padded line followed by another body
line still errors `short line in armor body is not the last line`. A 400-case structural mutation
fuzz (char substitution, line truncation/extension/duplication/deletion, stray `=`) over base files
at sizes 0/38/39/40/100 produced **zero** accept/reject disagreements with `age` — the fix opens no
acceptance hole and over-rejects nothing.

**Severity + who is affected** — **correctness**, but with the highest *user* impact in this survey:
about 4% of arbitrary armored age files, and about 4% of AgeSharp's own armored encrypted identity
files, are unreadable by v0.2.

**API-neutral?** — Yes; `DearmorStream` is internal, `PublicAPI.Shipped.txt` untouched.

**Fix shape** — three edits, all inside `DearmorStream.cs`:

1. Delete the width-based rejection at `:103-104`.
2. `:107` — gate canonical-padding validation on the presence of padding, not width:
   `if (line.Contains('=')) ValidateCanonicalPadding(line.AsSpan());` — must run **after**
   `Convert.TryFromBase64Chars`, as it does today, so malformed lines fail decode first.
3. `:143` — a padded line ends the body regardless of width:
   `if (line.Length < ColumnsPerLine || line[^1] == '=') _lastLineWasShort = true;`

Equivalently: track the final line by decoded byte count (`bytesWritten < MaxDecodedPerLine`), which
is exactly go-age's rule. `next-version` has the same fix in a renamed file
(`Age/Format/ArmorDecoder.cs`, `DecodeBodyLine:72` and `ValidateBodyLine:94`), and that part of its
change is not entangled with the API redesign — it ports verbatim onto main's file.

**Confidence** — certain; reproduced and the fix verified.

---

<a id="c2"></a>
### C2 — The armor path disposes the caller's stream

**Location** — root cause `Age/Format/NewlineBoundedStream.cs:61-67` (`Dispose` calls
`inner.Dispose()`); wrapper chain `Age/Format/AsciiArmor.cs:48-50` (`StreamReader(..., leaveOpen:
false)`); `Age/Format/DearmorStream.cs:189-195`. Consumers: `Age/AgeEncrypt.cs:281-282`
(`DeArmorIfNeeded` returns `needsDispose = true`) with `Age/Crypto/DecryptStream.cs:157`
(`if (ownsStream) ciphertext.Dispose()`), `Age/AgeHeader.cs:81-82` (`finally`),
`Age/AgeRandomAccess.cs:223` (`using var dearmored`).

**What is wrong** — Disposing the returned `DearmorStream` cascades all the way down to the caller's
ciphertext stream. So the caller's stream is closed for armored input and left open for binary
input. This contradicts `CLAUDE.md`'s own rule ("the library never disposes a caller's stream") and
the `AgeRandomAccess` constructor's own XML doc ("The caller retains ownership of the stream.").
`AgeHeader.Parse` is documented as merely leaving the stream "positioned wherever header reading
stopped" — it actually closes it.

**Reproduction** — `Tracked : MemoryStream` counting `Dispose(true)`; encrypt 100 bytes twice, once
armored, once binary:

```
Decrypt          binary   callerStreamDisposed=False
Decrypt          armored  callerStreamDisposed=True
DecryptReader    binary   callerStreamDisposed=False
DecryptReader    armored  callerStreamDisposed=True
AgeHeader.Parse  binary   callerStreamDisposed=False
AgeHeader.Parse  armored  callerStreamDisposed=True
RandomAccess     binary   callerStreamDisposed=False
RandomAccess     armored  callerStreamDisposed=True
```

User-visible consequence, reproduced:

```csharp
var s = new Tracked(armoredBytes);
AgeEncrypt.Decrypt(s, o1, id);
s.Position = 0;
AgeEncrypt.Decrypt(s, o2, id);
// -> ObjectDisposedException: Cannot access a closed Stream.
```

The identical binary-input sequence succeeds.

**Verified clean on the encrypt side:** `ArmorStream.Dispose` (`:119-124`) disposes `_source`, but
that source is the library-created `EncryptStream`, whose `Dispose`
(`Age/Crypto/EncryptStream.cs:151-165`) never touches the caller's plaintext. Armored encryption does
not leak ownership. Also confirmed no leak is introduced on the `AgeRandomAccess` path: its `Dispose`
(`:126-133`) disposes only the library-created `_armoredBinaryInput` `MemoryStream`.

**Severity + who is affected** — **correctness**. Any library caller passing a long-lived
`FileStream`/`MemoryStream` and armored input. `Age.Cli` is unaffected in practice.

**API-neutral?** — Yes; `NewlineBoundedStream`, `AsciiArmor` and `DearmorStream` are all internal,
and `NewlineBoundedStream` is constructed at exactly one site (`AsciiArmor.cs:48`).

**Fix shape** — Give `NewlineBoundedStream` an `ownsInner`/`leaveOpen` ctor parameter (default
`false` to keep any other internal caller working) and pass `leaveOpen: true` from
`AsciiArmor.Dearmor`. Keep the `StreamReader` at `leaveOpen: false` so it still disposes the bounded
wrapper — passing `leaveOpen: true` to *both* is redundant. The existing `needsDispose`/`ownsStream`
plumbing then disposes only library-created objects. Verified: applied, rebuilt with
`TreatWarningsAsErrors` (0 warnings), probe reports `callerDisposed=False` on all eight rows,
armored reuse succeeds, suite stays green (431 + 143). `next-version` fixed this structurally by
rewriting the dearmor path (its `DearmorStream` has no `Dispose` override, `PeekableStream.cs:3`
comments "Never disposes inner") — that rewrite is entangled with the v0.3 API and must **not** be
backported.

**Note for the release notes:** this is a behaviour change in a patch release — it stops closing a
stream some callers may have come to rely on being closed. It restores the documented contract, so
it is a fix rather than a regression, but it should be called out.

**Confidence** — certain; reproduced independently by two investigators.

---

<a id="c3"></a>
### C3 — Culture-sensitive `StartsWith` mis-frames header lines

**Location** — `Age/Format/Header.cs:33`, `:38`, `:56`; `Age/Format/Stanza.cs:96`. Same
one-argument-overload pattern also at `Age/Plugin/PluginConnection.cs:95`,
`Age/AgeKeygen.cs:103-104,124-128`, `Age/Recipients/PluginIdentity.cs:165`,
`Age/Recipients/PluginRecipient.cs:155`, `Age.Cli/AgeCommand.cs:146,153`,
`Age.Cli/KeygenCommand.cs:88,94`.

**What is wrong** — `Header.Parse` decides what a header line *is* with `line.StartsWith("-> ")` /
`StartsWith("---")` / `StartsWith("--- ")`. The one-argument `string.StartsWith(string)` overload is
`StringComparison.CurrentCulture`, not `Ordinal`. Under ICU collation the C0 control characters and
DEL are completely ignorable, and `HeaderReader.ValidateByte` (`HeaderReader.cs:82-91`) rejects only
CR and bytes > 0x7F — so 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F and 0x7F reach the comparison. A line whose
raw bytes are `2D 01 01 3E 20 …` (`-\x01\x01> foo bar`) therefore satisfies `StartsWith("-> ")` and
is parsed as a stanza with type `>` and args `["foo","bar"]`; the charset validation never sees the
control bytes because `line[3..]` slices past them.

Two consequences: (1) main accepts and fully decrypts files that `age` v1.3.1 and rage reject as
malformed — Go compares raw byte prefixes (`internal/format/format.go:172`,
`bytes.HasPrefix(line, stanzaPrefix)`) — i.e. main is more permissive than the spec ABNF
`arg-line = "-> " argument *(SP argument) LF`; (2) because `CurrentCulture` collapses to `Ordinal`
in globalization-invariant mode, **the same library gives different answers depending on the
consuming app's build**. `Age.Cli.csproj:13-16` sets `<InvariantGlobalization>true</InvariantGlobalization>`
inside a `Condition="'$(PublishAot)' == 'true'"` group, so the AOT binary that `make` produces and
the shipped NuGet library disagree about whether a given file is valid.

**Reproduction** — files built via main's own public API (real `X25519Recipient.Wrap` stanza, correct
HKDF+HMAC header MAC, real payload) with an extra pseudo-stanza line before the real one:

```
$ age -d -i id.txt ctrl_stanza.age
age: error: failed to read header: failed to parse header:
     malformed stanza opening line: "-\x01\x01> foo bar\n"

$ Age.Cli -d -i id.txt ctrl_stanza.age
hello age

$ DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 Age.Cli -d -i id.txt ctrl_stanza.age
age: unexpected line in header: -\x01\x01> foo bar
```

Reproduced for `\x00`, `\x01` and `\x7f`. Step 3 is also proof the fix is sufficient: invariant mode
makes `StartsWith` ordinal and the file is then rejected with the same verdict as `age`.

Primitive confirmation (.NET 10, en-DE):

```
"\x01-> X25519 abc".StartsWith("-> ")                            => True
"\x01-> X25519 abc".StartsWith("-> ", StringComparison.Ordinal)  => False
"-\x01\x01> foo bar".StartsWith("-> ")                           => True   (ordinal: False)
"\x01--- MAC".StartsWith("---")                                  => True   (ordinal: False)
```

*Refinement, so nobody over-claims:* "strictly more permissive" is slightly too strong — a leading
control byte (`"\x01-> foo bar"`) is still rejected by main, though with a different error. The
mis-framing bites when the control bytes sit *inside* the prefix.

**Severity + who is affected** — **correctness / conformance and determinism**. Not an
authentication break: the header MAC covers the raw bytes and is verified after unwrap, so an
attacker without the file key cannot inject a line. It matters wherever a Go-based validator fronts
a .NET-based consumer, and wherever the AOT and NuGet builds are expected to agree.

**API-neutral?** — Yes; internal parsing code only.

**Fix shape** — Add `StringComparison.Ordinal` to every prefix/suffix comparison on parsed wire
data, starting with `Header.cs:33,38,56` and `Stanza.cs:96`. Enabling CA1307/CA1310 in the build
would prevent regressions. Optional belt-and-braces: extend `HeaderReader.ValidateByte` to reject
bytes < 0x20 other than LF, and 0x7F — no legitimate age header contains them. **Not fixed on
`next-version`** (its `Header.cs:29/34/52` have the identical culture-sensitive calls; and its
`HeaderReader.PrefillAsync` *does* use `Ordinal` for its `---` check, which makes its own sync and
async paths disagree). Apply to both branches.

**Confidence** — certain; reproduced.

---

<a id="c4"></a>
### C4 — A plugin returning more than one recipient-stanza has all but the last silently discarded

**Location** — `Age/Recipients/PluginRecipient.cs:61` — `result = ParseRecipientStanza(args, body);`
is an **assignment** inside the read loop, not an append. Dispatch site
`Age/AgeEncrypt.cs:230` (`header.Stanzas.Add(recipient.Wrap(fileKey));`).

**What is wrong** — The spec's own `recipient-v1` example shows a plugin emitting two
recipient-stanzas for FILE_INDEX 0, and go-age does `stanzas = append(stanzas, …)`
(`references/go-age/plugin/client.go:128`). main keeps only the last stanza and reports success.

**Reproduction — end to end, including permanent data loss.**

*(a) Observation.* Fake `age-plugin-multi` emits `-> recipient-stanza 0 multi-a` then
`-> recipient-stanza 0 multi-b`.

```
AgeSharp PluginRecipient.Wrap returns:  STANZA type=multi-b ...       (multi-a gone)
                                        protocol log shows main sent `ok` to both
age v1.3.1 produces a header with BOTH:
    -> multi-a
    QUFBQS70sg6WjNTEGAGGkwhrwOQ
    -> multi-b
    QkJCQi70sg6WjNTEGAGGkwhrwOQ
```

*(b) Data loss.* Fake `age-plugin-split` XOR-splits the file key across two stanzas of the same
FILE_INDEX (both needed to recover).

```
age encrypt then age decrypt : round-trips, prints "hello"
AgeSharp encrypt             : exit 0, "ENCRYPTED", header contains ONLY `-> split-b`
age -d on that AgeSharp file : age: error: no identity matched any of the recipients  (exit 1)
AgeSharp cannot decrypt it either.
```

The plaintext is gone and nothing warned the user.

**Severity + who is affected** — **correctness**, with silent permanent data loss. Anyone using a
plugin that emits multiple stanzas: share splitting, group/multi-slot recipients, a key stanza plus a
metadata stanza.

**API-neutral?** — Yes, in the form below. `recipient.Wrap(` has exactly **one** call site in the
library (`Age/AgeEncrypt.cs:230`), which is what makes the internal-interface approach work.

**Fix shape** — Two options; ship at least (2).

1. Add `internal interface IMultiStanzaRecipient { IReadOnlyList<Stanza> WrapAll(ReadOnlySpan<byte>
   fileKey); }`, implement it on `PluginRecipient` with the accumulating loop, and in
   `BuildHeaderAndFileKey` do
   `if (recipient is IMultiStanzaRecipient m) header.Stanzas.AddRange(m.WrapAll(fileKey)); else header.Stanzas.Add(recipient.Wrap(fileKey));`.
   Internal types need no `PublicAPI.Unshipped.txt` entry, so the public surface is unchanged.
2. Keep public `Wrap` working by having it throw `AgePluginException` when the plugin produced more
   than one stanza — this converts silent permanent data loss into a clean failure, which is the
   safety-critical half.

`next-version` fixed this by changing `IRecipient.Wrap` to return `IReadOnlyList<Stanza>`
(commit `fd16800`) — that is an API break and must **not** be backported.

**Confidence** — certain; reproduced end to end.

---

<a id="c5"></a>
### C5 — identity-v1 sends a distinct FILE_INDEX per stanza

**Location** — `Age/Recipients/PluginIdentity.cs:52` —
`string[] args = [i.ToString(), s.Type, .. s.Args];`

**What is wrong** — FILE_INDEX identifies the **file**, not the stanza. The spec: "Duplicate file
indices indicate stanzas that are from the same file header, and wrap the same file key." main is
decrypting one file, so every stanza must carry index `0`. go-age does exactly that:
`Args: append([]string{"0", rs.Type}, rs.Args...)` (`references/go-age/plugin/client.go:247`).
Consequences: (a) a plugin needing several stanzas of one file can never reassemble them; (b) the
spec rule "if any known stanza is structurally invalid … MUST NOT unwrap any stanzas with the same
FILE_INDEX" is defeated; (c) the plugin is asked to unwrap N phantom files and may legitimately reply
with N `file-key`s, which main overwrites one over another.

**Reproduction**

*(a) Observation.* Decrypting a 2-stanza header, AgeSharp's wire trace vs `age`'s:

```
AgeSharp:  -> recipient-stanza 0 multi-a      age:  -> recipient-stanza 0 multi-a
           -> recipient-stanza 1 multi-b            -> recipient-stanza 0 multi-b
```

*(b) Interop failure.* With `age-plugin-split` (file key XOR-split across two stanzas of one file):

```
$ printf hello | age -r age1split1qypqxpq4ga9k9 -o split-go.age     # header: -> split-a / -> split-b
$ age -d -i <(echo AGE-PLUGIN-SPLIT-1QYPQX4GPKCL) split-go.age
hello                                                               (exit 0)

AgeSharp main on the SAME file:
  Age.NoIdentityMatchException: no identity matched any recipient stanza
     at AgeEncrypt.UnwrapHeaderFromReader, Age/AgeEncrypt.cs:270
plugin-side log: "cannot recover file 0 have ['split-a']" / "cannot recover file 1 have ['split-b']"
```

**Severity + who is affected** — **correctness**. main cannot decrypt files the reference client
decrypts. Anyone using a multi-stanza plugin identity.

**API-neutral?** — Yes; one-token internal change.

**Fix shape** — `string[] args = ["0", s.Type, .. s.Args];`. `Age.Tests/PluginTests.cs:542-543`
asserts the buggy wire form (`-> recipient-stanza 0 X25519 a1` / `-> recipient-stanza 1 scrypt a2
18`) and must be updated. **Not fixed on `next-version`** — its `PluginIdentity.cs:75` still has
`i.ToString()`. Apply to both branches.

**Confidence** — certain; reproduced.

---

<a id="c6"></a>
### C6 — Plugin stderr is redirected but never drained: deadlock past 64 KiB

**Location** — `Age/Plugin/PluginConnection.cs:30` (`RedirectStandardError = true`). No reader for
`_process.StandardError` exists anywhere in the assembly — no `BeginErrorReadLine`, no
`ErrorDataReceived`.

**What is wrong** — The redirect creates a pipe nothing ever reads. Once the plugin writes past the
OS pipe buffer, its `write(2)` blocks; meanwhile the client is blocked in `TextReader.ReadLine()` on
stdout. Neither side can progress and there is no timeout — the call hangs indefinitely. go-age
leaves `cmd.Stderr` unset (discarded) unless `AGEDEBUG=plugin`, so it never deadlocks.

**Reproduction** — exact threshold, measured against a Release build with fake `age-plugin-noisy`
writing `NOISE_BYTES` to stderr before answering phase 2:

```
stderr=  16384 bytes: ok in 0.6s
stderr=  32768 bytes: ok
stderr=  65536 bytes: ok in 0.1s
stderr=  65537 bytes: HUNG (killed after 10s)
stderr= 131072 bytes: HUNG (killed after 10s)
```

65536 is the macOS/Linux default pipe capacity. Referee at 131072 bytes:
`printf hello | age -r age1noisy1qypqxpqxeplwt -o out.age` completes in 0.067 s, exit 0.

**Severity + who is affected** — **correctness** (a hard hang, no timeout). Any plugin built with
verbose/debug logging, or one retrying a hardware token in a loop.

**API-neutral?** — Yes; `PluginConnection` is internal, `ProcessStartInfo` config only.

**Fix shape** — Option (b) is strictly better. (a) Set `RedirectStandardError = false` so the plugin
inherits the client's stderr — one line, but louder than go-age (which discards unless
`AGEDEBUG=plugin`). (b) Keep the redirect and drain it off-thread: subscribe to
`ErrorDataReceived`, call `BeginErrorReadLine()` right after `Process.Start`, keep the last few KiB
in a bounded buffer, and append it to the `AgePluginException` message on failure — which is what the
spec asks for on encryption failure and which main currently cannot do at all. **Present on
`next-version` too** (identical `RedirectStandardError = true` with no reader).

**Confidence** — certain; reproduced with an exact threshold.

---

<a id="c7"></a>
### C7 — Raw `FormatException` / `ArgumentException` escape the plugin path

**Location** — two sites, same class, adjacent fix:

- `Age/Plugin/PluginConnection.cs:123` — `bodyChunks.Add(Base64Unpadded.Decode(bodyLine));`,
  unguarded.
- `Age/Plugin/PluginConnection.cs:88-107` (`ReadStanza`) does not run `ValidateStanzaString` over
  the parsed type and args, unlike `Stanza.Parse` (`Stanza.cs:104-111`);
  `Age/Recipients/PluginRecipient.cs:86` then feeds those raw strings to `new Stanza(...)`, whose
  `EnsureValidStanzaString` throws `ArgumentException` (`Stanza.cs:169-181`).

**What is wrong** — `PluginRecipient.Wrap` (`:29`) and `PluginIdentity.Unwrap` (`:24`) are both
documented `<exception cref="AgePluginException">`, and `CLAUDE.md` states that a raw BCL or
BouncyCastle exception reaching a caller is a bug. The sibling `DecodeOptionLabel`
(`PluginRecipient.cs:136-146`) already wraps `FormatException` correctly, so this is an inconsistency
inside the same feature.

**Reproduction**

*Base64 body.* Fake `age-plugin-bad` answers phase 2 with `-> recipient-stanza 0 bad` then
`!!!!not base64!!!!`:

```
System.FormatException: invalid base64 input
   at Age.Crypto.Base64Unpadded.DecodeWithPadding(...)  Base64Unpadded.cs:50
   at Age.Crypto.Base64Unpadded.Decode(...)             Base64Unpadded.cs:31
   at Age.Plugin.PluginConnection.ReadBody()            PluginConnection.cs:123
   at Age.Plugin.PluginConnection.ReadStanza()          PluginConnection.cs:103
No AgeException anywhere in the chain.
```

*Stanza charset.* Calling the public `new PluginRecipient(recip).Wrap(...)` against stub plugins:

```
plugin emits `-> recipient-stanza 0 X25519  extra`  (double space -> empty arg)
  -> System.ArgumentException: stanza type/argument cannot be empty (Parameter 'args')  isAgeException=False
plugin emits `-> recipient-stanza 0 X25\x01519 aaa`
  -> System.ArgumentException: invalid character in stanza type/argument: 0x01 (Parameter 'type')  isAgeException=False
```

Note the empty-arg case needs no exotic bytes at all — two consecutive spaces suffice.

**Severity + who is affected** — **correctness** (exception-contract violation). Reachable only via
a misbehaving or hostile local plugin binary. A caller doing the documented `catch (AgeException)`
crashes instead.

**API-neutral?** — Yes; `AgePluginException` already exists in `PublicAPI.Shipped.txt`.

**Fix shape** — Do both centrally in `PluginConnection`: wrap the `Base64Unpadded.Decode` call in
`ReadBody` in `try/catch (FormatException ex)` → `new AgePluginException($"plugin sent an invalid
stanza body: {ex.Message}", ex)` (the same guard should cover padded and non-canonical bodies —
`Base64Unpadded.Decode` throws `FormatException` at `:29` and `:68` too), and validate the parsed
type and each arg in `ReadStanza` the way `Stanza.Parse` does, throwing `AgePluginException`.
Validating in `ReadStanza` also covers `PluginIdentity`'s consumption of the same unvalidated
strings. **Present on `next-version` too.**

**Confidence** — certain; both halves reproduced.

---

<a id="c8"></a>
### C8 — `SshEd25519Identity.Unwrap` has no low-order guard

**Location** — `Age/Recipients/SshEd25519Identity.cs:103` (the reachable site); second unguarded
site at `:116`.

**What is wrong** — The first X25519 agreement (identity secret × attacker-supplied ephemeral share
from the stanza) runs with neither the `try/catch` nor the all-zero check that
`X25519Identity.Unwrap:135` has. BouncyCastle throws `System.InvalidOperationException("X25519
agreement failed")` for any low-order/identity ephemeral share, and nothing converts it, so it
propagates out of `AgeEncrypt.Decrypt` / `DecryptReader` / `DecryptDetached`.

**Full site inventory** (enumerated by grepping for `CalculateAgreement`, not by expectation — 8
calls across 5 files):

| # | site | guard? |
|---|---|---|
| 1 | `X25519Identity.cs:135` | **present** |
| 2 | `X25519Recipient.cs:63` | **present** |
| 3 | `XWing.cs:94` (Decaps) | **present** |
| 4 | `XWing.cs:58` (Encaps) | missing — reachable, see [C9](#c9) |
| 5 | `SshEd25519Identity.cs:103` | missing — reachable, **this finding** |
| 6 | `SshEd25519Identity.cs:116` | missing — not reachable |
| 7 | `SshEd25519Recipient.cs:58` | missing — not reachable, see [C10](#c10) |
| 8 | `SshEd25519Recipient.cs:71` | missing — not reachable |

**Reproduction**

```
1. ssh-keygen -t ed25519 -N '' -f keys/id_ed25519
2. AgeEncrypt.Encrypt(..., SshEd25519Recipient.Parse(pubLine))
3. Replace the 2nd argument of `-> ssh-ed25519 <tag> <ephShare>` with unpadded base64 of a
   low-order point (leave the tag intact so the identity does not early-return null)
4. AgeEncrypt.Decrypt(tampered, out, identity)

Observed for all 7 points tried (32 zero bytes; u=1; e0eb7a7c..b800; 5f9c95bc..11d7; p-1; p; p+1):
  System.InvalidOperationException: X25519 agreement failed        <-- not an AgeException

Identical tamper on an X25519 stanza gives, correctly:
  Age.AgeHeaderException: X25519 shared secret is all-zero (low-order or identity point)

main's CLI, same file:
  $ Age.Cli -d -i keys/id_ed25519 bad0.age
  age: internal error: X25519 agreement failed
  This is a bug. Please report it at https://github.com/pscheid92/AgeSharp/issues

Referee, same file:
  $ age -d -i keys/id_ed25519 bad0.age
  age: error: invalid X25519 recipient: crypto/ecdh: bad X25519 remote ECDH input: low order point
```

**Severity + who is affected** — **correctness, not security.** No zero shared secret is ever used:
BouncyCastle rejects the agreement, so `docs/spec/age.md:294`'s MUST is satisfied. What breaks is the
library's exception contract — a caller that catches `AgeException` to handle hostile files gets an
unhandled exception, and main's CLI reports a merely-malformed input file as a library bug. Anyone
decrypting untrusted files with an `ssh-ed25519` identity.

**API-neutral?** — Yes; the method body and `CryptoHelper` are both implementation detail. Note the
thrown type changes from `InvalidOperationException` to `AgeHeaderException`.

**Fix shape** — Add an internal `CryptoHelper.X25519Agree(priv, pub) -> byte[]` holding the
`try/catch` + all-zero check and route all 8 call sites through it. Site `:116` cannot yield zero if
`:103` succeeded (the clamped scalar puts the raw secret in the prime-order subgroup — Go discards
the second error with `_` for the same reason at `agessh.go:222,334`), but routing both costs
nothing. `next-version` does exactly this in `cffc59e`, extended in `df99387`; there the helper
throws `AgeFormatException`, which on main's hierarchy is `AgeHeaderException`.

**Confidence** — certain; reproduced independently by two investigators.

---

<a id="c9"></a>
### C9 — `XWing.Encaps` leaks raw BCL exceptions out of the public `Encrypt`

**Location** — `Age/Crypto/XWing.cs:45` (`MLKemPublicKeyParameters.FromEncoding`) and `:58`
(`agreement.CalculateAgreement`), both unguarded; reached from
`Age/Recipients/MlKem768X25519Recipient.cs:56`.

**What is wrong** — `XWing.Decaps` (`:89-105`) guards its agreement; `Encaps` does not — the
asymmetry is within the same file. And `MlKem768X25519Recipient.Parse` validates only HRP, the
1216-byte length and lowercase-ness, so a hostile `age1pq1…` string flows straight into both calls.
A malformed ML-KEM half surfaces as `System.ArgumentException`; a low-order X25519 half surfaces as
`System.InvalidOperationException` — both out of the public `AgeEncrypt.Encrypt`. This is the
**encrypt** side, so the untrusted input is a recipient string or recipients file: exactly the thing
a user copies from a website or a colleague.

**Reproduction** — through main's real public facade:

```
Encrypt(bad ek):    System.ArgumentException         isAgeException=False
                    msg: Input validation: Modulus check failed for ml-kem encapsulation
Encrypt(zero pkX):  System.InvalidOperationException isAgeException=False
                    msg: X25519 agreement failed

CLI:
  $ Age.Cli -r "$(cat hostilepq_all-zero.txt)" -o /dev/null p.txt
  age: internal error: X25519 agreement failed
  This is a bug. Please report it at https://github.com/pscheid92/AgeSharp/issues

Referee:
  $ age -r "$(cat hostilepq_all-zero.txt)" -o /dev/null < p.txt
  age: error: failed to wrap key for recipient #0: failed to set up HPKE sender:
       crypto/ecdh: bad X25519 remote ECDH input: low order point       (exit 1)
```

Reproduced for all-zero, u=1, and order-8 points; `Parse` accepted all of them.

**Do not let this get restated as a missing low-order check.** It is not. All 12 canonical bad
X25519 public keys were checked against `Wrap`: the 7 canonical ones (0, 1, both order-8 points,
p-1, p, p+1) are rejected by BouncyCastle; the 5 non-canonical ones (value + p, high bit set) are
accepted and produce a non-zero secret — and `age` v1.3.1 accepts those exact same 5 (verified,
exit 0). The only defect here is the **exception type**.

**Severity + who is affected** — **correctness**. Anyone encrypting to a PQ recipient string from an
untrusted source. One nuance: `ArgumentException` is already a documented exception on this method
(for the empty-recipients case), so a caller is not guaranteed to be catching only `AgeException`;
`InvalidOperationException` is wholly undocumented. Both violate `CLAUDE.md`'s explicit rule.

**API-neutral?** — Yes; `XWing` is `internal static`.

**Fix shape** — Local `try/catch` at `XWing.cs:45` and `:58` rethrowing as `AgeException` /
`AgeHeaderException`, mirroring `X25519Recipient.cs:61-72`. Falls out for free if the shared
`CryptoHelper.X25519Agree` helper from [C8](#c8) is introduced (that covers `:58`; `:45` still needs
its own catch). `next-version` fixed the agreement half in `df99387`.

**Confidence** — certain; reproduced.

---

<a id="c10"></a>
### C10 — `SshKeyParser` throws `ArgumentException` where `FormatException` is documented

**Location** — `Age/Crypto/SshKeyParser.cs:38` (the reachable half).
Latent companion: `Age/Recipients/SshEd25519Recipient.cs:58` and `:71` have no agreement guard
(symmetric with [C8](#c8), on the encrypt side).

**What is wrong** — `SshEd25519Recipient.Parse` is documented `<exception cref="FormatException">`
but BouncyCastle's `OpenSshPublicKeyUtilities.ParsePublicKey` throws `System.ArgumentException`, and
nothing converts it. main's CLI only catches `AgeException or FormatException`
(`Age.Cli/Program.cs:80`), so a malformed recipients file is reported as a library bug.

**Reproduction** — hand-built `ssh-ed25519` authorized_keys blobs carrying Ed25519 points y=1
(identity, order 1), y=0 (order 4), y=-1 (order 2), an order-8 point, and y=2 (off-curve):

```
All five rejected before ever reaching Wrap:
  System.ArgumentException: invalid public key    (FormatException=False, AgeException=False)
     from BouncyCastle inside SshKeyParser.ParsePublicKey, Age/Crypto/SshKeyParser.cs:38

CLI:
  $ Age.Cli -R hostile_y=2.pub -o /dev/null p.txt
  age: internal error: invalid public key
  This is a bug. Please report it at https://github.com/pscheid92/AgeSharp/issues

Referee, same five lines:
  y=1, y=0, y=-1: age: error: failed to wrap key for recipient #0:
                  crypto/ecdh: bad X25519 remote ECDH input: low order point
                  (Go ACCEPTS the key and fails cleanly at the agreement)
  y=2:            age: warning: ... ignoring unsupported SSH key ... / no recipients found
```

Because BouncyCastle rejects all of these at parse, the unguarded agreements at
`SshEd25519Recipient.cs:58` and `:71` are **latent, not exploitable**. They are reported here only
because they are the same one-line omission and because a future caller of the internal ctor, or a
BouncyCastle behaviour change, would turn them into [C8](#c8)'s twin. main being stricter than `age`
at parse time is fine per spec.

**Severity + who is affected** — **correctness** (exception-contract violation, reachable from a
malformed recipients file). The latent-agreement half alone would be hygiene.

**API-neutral?** — In signature terms yes; note it changes the observable exception type on the
public `SshEd25519Recipient.Parse` / `AgeKeygen.ParseSshRecipient` from `ArgumentException` to
`FormatException`. No `PublicAPI.*.txt` change, and it moves behaviour toward the documented
contract, but flag it in the patch notes — a caller currently catching `ArgumentException` would be
affected.

**Fix shape** — Two independent one-liners. (a) Route `SshEd25519Recipient.cs:58` (and `:71`) through
the shared guard from [C8](#c8) — `next-version`'s `cffc59e` covers both. (b) In
`SshKeyParser.ParsePublicKey`, wrap the BouncyCastle call so `ArgumentException` becomes
`throw new FormatException("invalid SSH public key", ex)` — wrapping rather than replacing preserves
the inner exception.

**Confidence** — certain; both halves reproduced.

---

<a id="c11"></a>
### C11 — Seeking relative to the end never verifies the final chunk (spec MUST)

**Location** — `Age/Crypto/RandomAccessDecryptStream.cs:6` (`_length`), `:11` (`Length`), `:43`
(`SeekOrigin.End`); root cause `Age/AgeRandomAccess.cs:156`.

**What is wrong** — `docs/spec/age.md:165-167`, verbatim: "Seeking relatively to the end of file MUST
first decrypt and verify that the last chunk is a valid final chunk." main's seekable path never
does. `Length` and `Seek(0, SeekOrigin.End)` are pure layout arithmetic over an unauthenticated byte
count.

**Reproduction** — encrypt 196608 bytes (3 full chunks), drop the last 5 ciphertext bytes:

```
age -d on truncated file: ok=False
AgeRandomAccess ctor OK.  PlaintextLength=196603  (real 196608)
Stream.Length=196603      Seek(0,End)=196603      -> no error raised
ReadAt(0,100) = 100 bytes, no error
```

Honest caveat, confirmed: a **full** read of this file *does* eventually throw
`AgePayloadException`, so no short plaintext is silently returned in this particular case. The defect
is that `Length`, `Position` and `Seek`-from-End are silently wrong. That is why this is ranked
correctness and not security, unlike [S2](#s2)/[S3](#s3).

**Severity + who is affected** — **correctness** (spec MUST violation). `AgeRandomAccess` library
callers.

**API-neutral?** — Yes; subsumed by the [S2](#s2) fix.

**Fix shape** — After eager final-chunk verification in `InitializeFromStream`, `PlaintextLength` and
therefore `Length`/`Seek(End)` become authenticated values, and the constructor throws
`AgePayloadException` on a truncated file.

**Confidence** — certain; reproduced.

---

<a id="c12"></a>
### C12 — `Read()` after `Dispose()` returns another renter's memory

**Location** — `Age/Crypto/DecryptStream.cs:42` (`Read` has no disposal check).
**Explicitly NOT `EncryptStream`** — see below.

**What is wrong** — After `Dispose`, `_plaintextBuffer` and `_ciphertextBuffer` belong to
`ArrayPool` again and may already be owned by someone else, yet `Read` continues to copy out of
`_plaintextBuffer` (`:49-57`) without touching the cipher.

**Reproduction**

```csharp
var s = AgeEncrypt.DecryptReader(new MemoryStream(ct), id);   // 200000-byte plaintext
s.Read(buf);            // buffers a chunk
s.Dispose();            // buffers zeroed and handed back to the pool
s.Read(buf)             // -> returns 100, NO ObjectDisposedException
```

Taken further: after disposing, letting an unrelated renter fill the recycled array with `0xAB` and
calling `Read` again **returned 100 bytes of that renter's `0xAB` data as though it were plaintext**.
So this is not merely a missing exception.

Two bounds worth stating rather than hiding:

- The window is bounded. Once the residual buffered plaintext is drained, the next chunk decryption
  hits the disposed `IAeadCipher` and throws `ObjectDisposedException`, so at most one 64 KiB
  buffer's worth of foreign data can be returned.
- `EncryptStream.Read` after `Dispose` **throws `ObjectDisposedException` immediately** (verified
  empirically), because it must encrypt a new chunk and hits the disposed cipher. It is incidentally
  protected — by the disposed cipher, not by a real guard — and is not currently a use-after-return.
  It should still get the guard for robustness.

**Severity + who is affected** — **correctness**. Requires API misuse (`Read` after `Dispose`) to
trigger, so it is not on par with [S2](#s2)/[S4](#s4).

**API-neutral?** — Yes; internal-only, and reuses the `_disposed` field introduced for [S4](#s4).

**Fix shape** — `ObjectDisposedException.ThrowIf(_disposed, this)` at the top of `Read` (and `Write`
on the writer side). `next-version` does this in `SeekableDecryptStream` (`:125`, `:157`) and
`DecryptStream`.

**Confidence** — certain; reproduced.

---

<a id="i1"></a>
### I1 — Armored input is not detected on a non-seekable stream

**Location** — `Age/Format/AsciiArmor.cs:13-14` is real but **is not the operative gate**. The
effective gates are the call-site guards `if (input.CanSeek && AsciiArmor.IsArmored(input))` at
`Age/AgeEncrypt.cs:281` and `Age/AgeHeader.cs:51`. `Age/AgeRandomAccess.cs:220` is **not** an
affected site — the constructor already throws
`ArgumentException("ciphertext stream must be seekable")` at `:47-48` before `DeArmorInput` is
reached. So there are **two** call sites to change, not three.

**What is wrong** — `IsArmored` detects the BEGIN marker by seeking (save `Position`, read, restore),
so on a non-seekable stream it gives up and returns `false`, and the raw armored text reaches the
header parser. The reference CLI decrypts armored stdin without difficulty.

**Reproduction** — `ForwardOnly` wrapper (`CanSeek = false`, delegates `Read`) over armored bytes:

```
Decrypt(nonseekable armored)          AgeHeaderException: unsupported version: -----BEGIN AGE ENCRYPTED FILE-----
DecryptReader(nonseekable armored)    AgeHeaderException: unsupported version: -----BEGIN AGE ENCRYPTED FILE-----
AgeHeader.Parse(nonseekable armored)  AgeHeaderException: unsupported version: -----BEGIN AGE ENCRYPTED FILE-----
Decrypt(nonseekable binary)           OK
```

The same bytes through a seekable `MemoryStream` decrypt correctly.

**Severity + who is affected** — **interop, and it is a *documented* limitation, not a silent lie.**
`AgeEncrypt.Decrypt` (`:53`), `DecryptReader` (`:188`) and `AgeHeader.Parse` (`:38`) all say
"Armored input is auto-detected when the stream is seekable", and `Age.Cli` buffers stdin into a
`MemoryStream` first (`Age.Cli/AgeCommand.cs:92-97`), so `cat file.age | Age.Cli -d` works. Only
library callers with a `NetworkStream`, `GZipStream`, `Console.OpenStandardInput` or an HTTP response
body are affected.

**API-neutral?** — In signature terms yes (`PeekableStream` would be internal, the two guards are
private helpers). But it *widens* accepted input rather than narrowing it, and the XML doc sentences
about seekability would have to be dropped in the same patch.

**Fix shape** — Add an internal lookahead wrapper. `next-version` already has exactly this:
`Age/Format/PeekableStream.cs` ("Lookahead rather than seeking, so armor detection works on a pipe")
plus `AsciiArmor.Detect` (`Age/Format/AsciiArmor.cs:20-35`) returning `(source, isArmored)` —
seekable inputs keep the save/restore path, non-seekable ones get a `PeekableStream` whose `Peek()`
is replayed on subsequent `Read`s. Porting means copying `PeekableStream` in as internal and changing
the two guards to take back a possibly-wrapped source rather than a bare `bool`.

**A cheaper alternative for a patch release:** fix only the error message. Detect the BEGIN-marker
prefix on the version-line error path and say so, instead of reporting the armor marker as an
"unsupported version". Full non-seekable armor support is a behaviour change that arguably belongs in
a minor release.

**Confidence** — certain (the failure); the fix was not built or tested.

---

<a id="i2"></a>
### I2 — `MlKem768X25519Recipient.Parse` accepts a structurally invalid ML-KEM public key

**Location** — `Age/Recipients/MlKem768X25519Recipient.cs:33-47` (`Parse`).

**What is wrong** — `Parse` validates HRP (`:37`), total length 1216 (`:40`) and lowercase-ness
(`:44`) and never decodes or validates the 1184-byte ML-KEM encapsulation key. Go's
`ParseHybridRecipient` calls `hpke.MLKEM768X25519().NewPublicKey`, which runs the
`ByteEncode`/`ByteDecode` round-trip (modulus) check and rejects immediately.

**Reproduction** — a recipient whose first 1152 ek bytes are `0xff`, bech32-encoded via `ToString()`
(round-trip verified against a known-good recipient first), fed to both implementations:

```
main:  MlKem768X25519Recipient.Parse(s)        -> ACCEPTED (no exception)
age:   age -e -r "$(cat badrecip_ek.txt)" p.txt
       exit=1
       age: error: malformed recipient "age1pq1llll…": invalid MLKEM768-X25519 public key
```

The X25519 half is a different matter: **neither** implementation validates `pk_X` at parse time, so
that is not a divergence and must not be folded into the fix.

**Severity + who is affected** — **interop**, not security. A tool that validates a recipients file
by parsing it reports the file as good and then fails mid-encryption, and the failure arrives as the
raw `ArgumentException` of [C9](#c9). main never emits such a string, and the encryption fails rather
than succeeding weakly.

**API-neutral?** — Yes; `Parse`'s signature and `FormatException` contract are unchanged.

**Fix shape** — After the length check, attempt
`MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, data[..1184])` inside a
`try/catch` and rethrow as `FormatException` (main's convention for `Parse` methods). Cache the
parameters object on the instance to avoid re-parsing in `Encaps`. **`next-version` has no equivalent
fix** — its `Parse` routes through `ParseHelpers.DecodeRecipientKey`, which is also HRP + length +
case only — so this must be written fresh.

**Confidence** — certain; reproduced against both implementations.

---

<a id="i3"></a>
### I3 — scrypt work factor hard-capped at 20, below Go's library default of 22

**Location** — `Age/Recipients/ScryptRecipient.cs:25` (`private const int MaxWorkFactor = 20`), used
both by `EnsureValidWorkFactor` (`:34-39`, `ArgumentOutOfRangeException` on construct) and by the
decrypt path (`:86-87`, `AgeHeaderException`).

**What is wrong** — `docs/spec/age.md:326-328` says the identity implementation "SHOULD apply an
upper limit to the work factor", so 20 is **legal** — this is spec-permitted policy, not a spec
violation. But Go's `ScryptIdentity` defaults `maxWorkFactor` to **22**
(`references/go-age/scrypt.go:129`), and `cmd/age`'s `LazyScryptIdentity`
(`cmd/age/encrypted_keys.go:37`) calls `NewScryptIdentity` without `SetMaxWorkFactor`, so even the
`age` CLI's decrypt path accepts 21/22. main refuses those files, and cannot produce them either.

**Reproduction** — closed empirically, with a genuine Go-produced file. A Go program built against
the vendored `references/go-age` clone (v1.3.1, commit `706dfc1`) calling
`age.NewScryptRecipient("pw").SetWorkFactor(21)` round-trips fine in Go in ~12 s. Feeding the
resulting real file (header `-> scrypt vsnpnvt+UjWDtmng6h5n8Q 21`) to main:

```
scrypt_wf21.age   Age.AgeHeaderException: scrypt work factor 21 exceeds maximum 20
```

Also verified directly on hand-built headers at 21 and 22. The ceiling check fires before scrypt is
ever run, so rejection is instant.

*Correction to a common rationale:* the rage half of the argument is weaker than it looks.
`references/rust-age/age/src/native/scrypt.rs:191` does set `max_work_factor = target + 4`, but
`target_scrypt_work_factor()` (`:72-88`) climbs from `log_n = 10` until one scrypt run takes ≥ 1 s,
and rage's *recipient* default is that same measured target (`:119`). Exceeding 20 on the encrypt
side needs a machine where 1 GiB of scrypt completes in under a second, which is not today's
hardware. **The solid case is Go's library**, demonstrated above.

**Severity + who is affected** — **interop**. Anyone receiving a passphrase-encrypted file produced
by a Go caller of `SetWorkFactor(21|22)`. The `age` CLI hardcodes 18, so `age -p` output is
unaffected.

**API-neutral?** — Yes; `MaxWorkFactor` is a private const.

**Fix shape** — Raise the **decrypt-side** ceiling to 22 by splitting out
`MaxAcceptedWorkFactor = 22` while leaving the encrypt-side constructor bound at 20 (or raise both).
Keeping 20 is a defensible policy under the spec's SHOULD — but then the XML doc should say plainly
that this is below Go's default and is a hard interop boundary, which it currently does not.

**Confidence** — certain; reproduced against a genuine go-age file.

---

<a id="i4"></a>
### I4 — Plugin FILE_INDEX never validated; a duplicate `file-key` silently replaces the previous one

**Location** — `Age/Recipients/PluginRecipient.cs:79-87` (`ParseRecipientStanza` checks
`args.Length >= 2` but ignores `args[0]`); `Age/Recipients/PluginIdentity.cs:69-74` (the `file-key`
case checks only `args.Length >= 1`, with no duplicate check).

**What is wrong** — main sends exactly one file key, so the index must always be `0`. go-age parses
it, rejects anything but 0 (`client.go:119-126` and `:272-282`), and rejects a second `file-key`
outright ("received duplicated file-key stanza"). main accepts a recipient-stanza addressed to a file
it never sent, accepts a `file-key` for a phantom index, and on a duplicate keeps the last while
leaving the discarded key material unzeroed on the heap.

**Reproduction** — fake `age-plugin-weird`:

```
recipient-v1, `-> recipient-stanza 7 weird ...`:
  AgeSharp: accepted into the header, ENCRYPTED, exit 0
  age:      malformed recipient stanza: unexpected index        (exit 1)

identity-v1, `-> file-key 42 <key>`:
  AgeSharp: PLAINTEXT=hello
  age:      malformed file-key stanza: unexpected index         (exit 1)

identity-v1, `-> file-key 9 <16 zero bytes>` then `-> file-key 0 <real key>`:
  AgeSharp: PLAINTEXT=hello (silently overwrote the bogus key)
  age:      malformed file-key stanza: unexpected index         (exit 1)
```

**Severity + who is affected** — **interop**. main enforces `fileKey.Length == 16`
(`AgeEncrypt.cs:272-273`) and then `header.VerifyMac`, so a bogus key cannot yield a wrong plaintext.
The harm is protocol non-conformance plus discarded key material left unzeroed.

**API-neutral?** — Yes; internal only.

**Fix shape** — In `ParseRecipientStanza`, require `args[0] == "0"` and throw
`AgePluginException("recipient-stanza has unexpected file index")` otherwise. In `PluginIdentity`'s
`file-key` case, require exactly one arg equal to `"0"`, and throw
`AgePluginException("duplicate file-key stanza")` when `result` is already non-null. **Ship together
with [C5](#c5)** — these validations only become meaningful once main itself sends `0` consistently.

**Confidence** — certain; all three sub-cases reproduced.

---

<a id="i5"></a>
### I5 — A `confirm` with zero arguments is answered with a fabricated "yes" label

**Location** — `Age/Recipients/PluginRecipient.cs:130` and the verbatim duplicate at
`Age/Recipients/PluginIdentity.cs:140`:
`var yes = args.Length > 0 ? DecodeOptionLabel(args[0]) : "yes";`

**What is wrong** — The spec's `confirm` form is
`(confirm, Base64(YES_STRING) [Base64(NO_STRING)]; MESSAGE)` — `YES_STRING` is mandatory. go-age
rejects anything other than 1 or 2 args (`client.go:359-361`). main invents the label `"yes"`, shows
the user a prompt whose affirmative button text was made up by the library rather than sent by the
plugin, and then answers `ok yes` to a malformed command.

**Reproduction** — fake plugin sends `-> confirm` with no args and body `press the button`:

```
AgeSharp: callback invoked as `[confirm] press the button y=yes n=`
          plugin log: client answered confirm with: ('ok', ['yes'], b'')
          wrap proceeds
age:      conf plugin: malformed confirm stanza: unexpected number of arguments   (exit 1)
```

**Severity + who is affected** — **interop**. Users of a plugin that emits a malformed `confirm`.

**API-neutral?** — Yes; no `IPluginCallbacks` change.

**Fix shape** — In **both** copies:
`if (args.Length is not (1 or 2)) throw new AgePluginException("malformed confirm stanza: unexpected number of arguments");`
before decoding. The `HandleConfirm`/`DecodeOptionLabel` pairs are duplicated verbatim across
`PluginRecipient` and `PluginIdentity` — edit both.

**Confidence** — certain; reproduced.

---

<a id="h1"></a>
### H1 — `Header.ComputeMac` never zeroes the derived header MAC key

**Location** — `Age/Format/Header.cs:90`
(`var hmacKeyBytes = CryptoHelper.HkdfDerive(fileKey, ReadOnlySpan<byte>.Empty, "header", 32);`),
reached from `:82` (`VerifyMac`) and `:113` (`WriteTo`). `grep -c ZeroMemory Age/Format/Header.cs`
→ 0 (the only `CryptographicOperations` call in the file is `FixedTimeEquals` at `:83`).

**What is wrong** — A 32-byte file-key-derived secret is left on the GC heap on every encrypt and
every decrypt. Every other derived key on main is zeroed by its owner (`wrapKey` in
`X25519Identity.cs:162`, `X25519Recipient.cs:91`, `SshEd25519Identity.cs:129`,
`SshEd25519Recipient.cs:86`; payload key by the stream's dispose) — this one site is the omission.

**Reproduction** — heap probe with a known file key, 301 decrypts:

```
residual copies of the 32-byte HEADER MAC KEY : 598
zeroed 32-byte control                        : 1
```

~2 copies per decrypt.

**Severity + who is affected** — **hygiene, deliberately not "security".** Recovering the header MAC
key does not yield the file key — it is a one-way HKDF output — and it only authenticates a header
the attacker already has. Forging a header MAC does not let an attacker read or re-wrap the payload,
which still needs the file key. That is precisely why this is rated below [S8](#s8) even though the
mechanism is identical; one investigator rated it security and that view is recorded here so the
disagreement is visible rather than silently resolved.

**API-neutral?** — Yes; `Header` is internal.

**Fix shape**

```csharp
var hmacKeyBytes = CryptoHelper.HkdfDerive(...);
try { return CryptoHelper.HmacSha256(hmacKeyBytes, headerBytes); }
finally { CryptographicOperations.ZeroMemory(hmacKeyBytes); }
```

Do **not** import `next-version`'s `stackalloc` form (`Age/Format/Header.cs:85-88`) — it depends on
the v0.3 span-filling `HkdfDerive`. Same attribution caveat as [S8](#s8): `HMACSHA256.HashData` also
copies a ≤64-byte key into its own block buffer, so this reduces rather than eliminates residue.

**Confidence** — certain; reproduced.

---

<a id="h2"></a>
### H2 — `ScryptRecipient` clears outside `finally`; the passphrase is held as a `string`

**Location** — `Age/Recipients/ScryptRecipient.cs:51` and `:96` (straight-line `ZeroMemory(wrapKey)`
after the ChaCha calls at `:50`/`:95`), `:132` (straight-line `ZeroMemory(passphraseBytes)` after
`SCrypt.Generate` at `:130`), `:20` (primary-constructor `string passphrase`, captured for the
object's lifetime).

**What is wrong** — Two separate problems.
**(a)** The `ZeroMemory` calls are straight-line, not in `finally`. If the intervening call throws,
the 32-byte scrypt wrap key or the UTF-8 passphrase survives.
**(b)** The primary constructor captures `string passphrase` for the object's lifetime. A string
cannot be zeroed, `ScryptRecipient` is not `IDisposable`, and `DeriveWrapKey` re-encodes it to a
fresh UTF-8 array on every single `Wrap`/`Unwrap`.

**Reproduction — NOT REPRODUCED.** Path (a) needs a forced allocation failure and (b) is a property
of the type rather than an event. Both are certain by inspection.

Throw reachability for (a) was walked and is **thin**: `CryptoHelper.ChaChaEncrypt` at `:50` is called
with a validated 32-byte key and 12-byte nonce, and `CryptoHelper.ChaChaDecrypt` at `:95` swallows
`AuthenticationTagMismatchException` internally and returns null, so neither realistically throws.
The one genuinely reachable trigger is `OutOfMemoryException` from `SCrypt.Generate` at `:130` — and
that one *is* attacker-influenced, since the decrypt path takes the work factor from the stanza up to
`MaxWorkFactor` 20, i.e. a ~1 GiB allocation on demand.

**Severity + who is affected** — **hygiene** (defence in depth on a thin path). Passphrase users.

**API-neutral?** — **(a) yes, (b) no.** `ScryptRecipient(string passphrase, int workFactor = 18)` is
public shipped surface and the type is not `IDisposable`; `next-version`'s fix replaces the whole
type with `Passphrase` (stores `byte[]`, adds `ReadOnlySpan<char>` constructors, implements
`IDisposable` — `Age/Recipients/Passphrase.cs:19-90`), which is new public surface plus a rename.

**Fix shape** — Backport **(a) only**: three `try/finally` insertions around the ChaCha calls and
`SCrypt.Generate`. Add a documentation remark stating that the passphrase string cannot be zeroed.
Set expectations honestly: fixing (a) does not help much while (b) stands, because the passphrase is
re-encoded to a fresh uncleared UTF-8 array on every `Wrap`/`Unwrap` anyway.

**Confidence** — certain on the code facts; not reproduced.

---

<a id="h3"></a>
### H3 — The plugin wire path pushes secrets through unzeroable strings

**Location** — `Age/Plugin/PluginConnection.cs:70` (`var encoded = Base64Unpadded.Encode(body);`)
and `:110-142` (`ReadBody`); `Age/Crypto/Base64Unpadded.cs:19` (`return new string(...)`);
`Age/Recipients/PluginRecipient.cs:45` (`fileKey.ToArray()`);
`Age/Recipients/PluginIdentity.cs:72` (`result = body`) and `:123-124` (the PIN).

**What is wrong** — Three secrets cross this wire and none is cleaned up.
(1) Outbound: `SendWrapRequest` does `conn.WriteStanza("wrap-file-key", [], fileKey.ToArray())` — an
uncleared heap copy of the raw file key — and `WriteStanza` then base64-encodes it into an immutable
string.
(2) Inbound: `ReadBody` accumulates the `file-key` stanza via `Base64Unpadded.Decode(bodyLine)` into
a `List<byte[]>` (`:123`), copies the chunks into `body` (`:135-139`) and clears none of them; and
`_reader.ReadLine()` already produced a string holding the base64 of the file key.
(3) `PluginIdentity.HandleCommonStanza:124` answers `request-secret` with
`Encoding.UTF8.GetBytes(value)` — the user's PIN — never cleared, then base64-encodes it into another
unzeroable string.

**Reproduction — NOT REPRODUCED.** Exercising it needs an `age-plugin-*` binary and a heap scan;
neither was done for these specific needles. The code facts are certain by inspection.

Two refinements: for a 16-byte file key `maxLen` is 24, under the 256-char `StackAllocThreshold`, so
the intermediate char buffer is stack-allocated and only the resulting immutable **string** is
heap-resident (a long PIN can exceed the threshold and take the heap path). And `WriteStanza` writes
into a `StreamWriter` whose internal char buffer *also* retains the base64 — another copy the fix
cannot reach.

**Severity + who is affected** — **hygiene**, deliberately not security. There is no
attacker-triggerable path, and the file key already crosses an OS pipe to the child in cleartext by
protocol design, so the marginal exposure added by the string is real but defence-in-depth. Plugin
users.

**API-neutral?** — Most of it. `PluginConnection`, `PluginRecipient.SendWrapRequest` and
`Base64Unpadded` are all internal. **Not neutral:** `IPluginCallbacks.RequestValue(string!, bool)
-> string!` is `PublicAPI.Shipped.txt:42`, so the PIN exists as an unzeroable string before the
library ever sees it; `next-version` split out a `char[]`-returning `RequestSecret`
(`Age/Plugin/PluginProtocol.cs:53-66`, commit `08facf6`) — that is a public interface change and must
**not** be backported.

**Fix shape** — Port only the encode half of `08facf6`: add internal
`Base64Unpadded.MaxEncodedLength(int)` and a span-writing `Encode(ReadOnlySpan<byte>, Span<char>)`
overload, have `WriteStanza` encode into an `ArrayPool<char>` rental and clear it with
`ZeroMemory(MemoryMarshal.AsBytes(...))` in a `finally` (`next-version PluginConnection.cs:90-116`).
Clear `ReadBody`'s chunk arrays and `PluginIdentity`'s unwrapped file key. Hoist and clear the
`wrap-file-key` `ToArray()` copy and the PIN's UTF-8 array. Leave `IPluginCallbacks` alone and
document the residual.

**Confidence** — certain on the code facts; not reproduced.

---

<a id="h4"></a>
### H4 — `X25519Identity.Unwrap` allocates the shared secret outside its `try`

**Location** — `Age/Recipients/X25519Identity.cs:132-164`; the unguarded window is `:136-151`.

**What is wrong** — `sharedSecret` is allocated at `:132` and filled at `:135`, but the `try/finally`
that zeroes it does not open until `:152`. Everything between — the `InvalidOperationException`
catch, the all-zero check, `PublicKeyParams.GetEncoded()`, the salt concatenation and
`CryptoHelper.HkdfDerive` — runs with the shared secret unprotected.

**Reproduction — NOT REPRODUCED**, and the practical exposure was checked and found to be **nil**:
on the two paths that actually throw (BouncyCastle rejecting the agreement, and the all-zero check at
`:143`) `sharedSecret` is by definition all-zero, so nothing sensitive is abandoned. The remaining
throws are unreachable in practice — `PublicKeyParams` (`:32-39`) is
`new X25519PrivateKeyParameters(_rawPrivateKey).GeneratePublicKey()`, which cannot throw for a
32-byte array even after `Dispose` has zeroed it, and `HkdfDerive` can only throw on OOM.

**Severity + who is affected** — **hygiene** — a genuine structural nit with no observable failure.
**Do not present it to users as a fixed vulnerability.**

**API-neutral?** — Yes; method body only.

**Fix shape** — Move the `try {` to immediately after the `CalculateAgreement` call so the `finally`
covers the all-zero check, the salt build and the HKDF. Cheap insurance, worth taking while the file
is already open for [S8](#s8).

**Confidence** — certain on the structure; no reachable exposure demonstrated.

---

<a id="h5"></a>
### H5 — `AgeRandomAccess` does not zero a decrypted chunk on one error path

**Location** — `Age/AgeRandomAccess.cs:179-184` (`DecryptChunkAt`).

**What is wrong** — `DecryptChunkAt` decrypts into a fresh `byte[]` and then throws
`AgePayloadException` if the final chunk is empty with predecessors, returning without zeroing.
`ReadAt` (`:104`) zeroes the chunk on the normal path, so the omission is only on this error path.

**Reproduction — NOT REPRODUCED, and there is nothing to reproduce.** On the only path that throws,
the guard condition is `plaintext.Length == 0`, so the abandoned array is a **zero-length**
`byte[]` — there is literally nothing to leak. The fallback rationale (a fault in the `ReadAt` copy
loop) is also empty: `:100-102` is arithmetic plus a `Span.CopyTo` whose bounds are computed from the
same values, with no reachable throw. The sibling allocation at `StreamEncryption.cs:136` was also
checked — on authentication failure the plaintext buffer is abandoned, but .NET's
`ChaCha20Poly1305` and the managed `AeadCipher` both clear the destination on tag mismatch, so again
no residue.

**Severity + who is affected** — **hygiene, and effectively a no-op change.**

**API-neutral?** — Yes.

**Fix shape** — Zero `plaintext` before the throw, or `try/finally` in `ReadAt`. **Recommendation:
include only if the patch already touches this file for [S2](#s2)/[S3](#s3); do not list it in
release notes as a security fix.**

**Confidence** — the code observation is certain; the defect is not.

---

<a id="h6"></a>
### H6 — Every mlkem stanza re-runs full ML-KEM keygen: ~7x pre-auth CPU vs the reference

**Location** — `Age/Crypto/XWing.cs:76` (`Decaps` calls `ExpandSeed` per stanza) and `:122-138`;
`Age/Recipients/MlKem768X25519Identity.cs:27` (`Recipient` recomputed on every property access).

**What is wrong** — `XWing.Decaps` re-derives the identity from scratch on every call: SHAKE-256
expansion plus `MLKemPrivateKeyParameters.FromSeed`, which is a full ML-KEM-768 KeyGen, **per stanza
tried**. Go's `HybridIdentity` holds a materialised `hpke.PrivateKey` and only decapsulates. Recipient
stanzas must be unwrapped before the header MAC can be checked
(`Age/AgeEncrypt.cs:262-264` iterates, `:275` verifies), so this is attacker-controlled work on
unauthenticated input, bounded only by `AgeLimits.MaxHeaderBytes` (16 MiB ≈ 10,700 mlkem stanzas at
~1.56 KiB each).

**Reproduction** — 1.6 MiB header, 1000 decoy PQ recipients, real identity last, encrypted by
`age -R`:

```
age (Go), 3 runs      : 0.10 / 0.09 / 0.09 s user
main (.NET), 3 runs   : 0.602 / 0.605 / 0.622 s user
```

In-process microbenchmark (Release, 100 iterations): `Unwrap` of a non-matching mlkem stanza
**1.065 ms**, `Recipient` property **0.489 ms**, `Wrap` 1.139 ms. `Recipient` is not even
reference-stable across accesses (`ReferenceEquals` → False), confirming full recomputation — so
`ToString()` in a loop is unexpectedly expensive.

Extrapolating 0.6 s per 1000 to the 16 MiB ceiling gives **~6.5 s** for main against ~1 s for `age`.

**Severity + who is affected** — **hygiene.** This is a bounded constant-factor amplification (~6-7x)
on a path the reference implementation also walks, not an unbounded or asymptotic DoS. Do not inflate
it.

**API-neutral?** — Yes, both halves.

**Fix shape** — Two independent internal caches.
1. `MlKem768X25519Identity`: `private MlKem768X25519Recipient? _recipient;` and
   `_recipient ??= new(XWing.GeneratePublicKey(_seed))`. Benign race, idempotent value.
   `next-version` does exactly this (`MlKem768X25519Identity.cs:20/35`, `X25519Identity.cs:22/36`)
   and it lifts directly. Side effect worth noting: caching makes `Recipient` reference-stable, so a
   caller putting repeated accesses into a `HashSet` now sees one entry where it previously saw two.
   That is a fix, not a break.
2. Cache the expanded `MLKemPrivateKeyParameters` / `X25519PrivateKeyParameters` / `pkX` on the
   identity, via an internal overload of `HpkeHelper.OpenBase` / `XWing.Decaps` taking the expanded
   key instead of the seed. The cached objects must be treated as read-only because
   `MlKem768X25519Identity.cs:9-11` promises instances are safe for concurrent `Unwrap` (BouncyCastle
   parameter objects are immutable, so this holds). **Not fixed on `next-version`** — its
   `XWing.cs:72` still calls `ExpandSeed` inside `Decaps` — so this half must be written fresh.

**Confidence** — certain; independently measured.

---

<a id="h7"></a>
### H7 — Plugin `Dispose` stalls 5 s then abandons a process that has not exited

**Location** — `Age/Plugin/PluginConnection.cs:144-161`; the unchecked wait is `:158`.

**What is wrong** — `Dispose` closes stdin, calls `_process.WaitForExit(5000)`, **discards the
bool**, then `_process.Dispose()` regardless. `StandardOutput` is never closed. A plugin that does not
exit on stdin EOF keeps running detached after the AgeSharp call returns, holding whatever it acquired
(a YubiKey/PC-SC session, a TPM handle, an agent socket) and continuing to hold the file key in its
memory. The caller also pays a 5-second stall with no diagnostic. go-age closes stdin **and** stdout,
sends `os.Interrupt`, then blocks on `cmd.Wait()`.

**Reproduction** — fake `age-plugin-zombie` ignores SIGINT and sleeps 600 s after `done`:

```
AgeSharp: Wrap returns the correct stanza, total wall time 5.4 s, probe exits.
One second later:
  $ pgrep -fl age-plugin-zombie
  66387 ... age-plugin-zombie --age-plugin=recipient-v1        (still alive)
```

**Severity + who is affected** — **hygiene** (resource leak plus a 5 s stall). Users of a plugin that
does not exit promptly.

**API-neutral?** — Yes; internal only.

**Fix shape** — Also close/dispose the stdout reader, and if `!_process.WaitForExit(5000)` call
`_process.Kill(entireProcessTree: true)` followed by a short `WaitForExit` before `Dispose`.
Optionally shorten the grace period. **Present on `next-version` too**
(`PluginConnection.cs:70` there has the identical `WaitForExit(5000)` with no `Kill`).

**Confidence** — certain; reproduced.

---

<a id="h8"></a>
### H8 — `StreamEncryption`'s whole-stream methods buffer everything and are test-only

**Location** — `Age/Crypto/StreamEncryption.cs:12-37` (`Encrypt`) and `:39-74` (`Decrypt`);
unreachable branches at `:67-68` and `:73`.

**What is wrong** — Both methods copy the whole input into a `MemoryStream` (`:14-16`, `:41-43`)
before doing any work, and hand out `GetBuffer()`. **No production code path calls them** — a grep
across `Age`, `Age.Cli`, `Age.Tests`, `Age.TestKit` and `Age.Benchmarks` finds callers only in
`Age.Tests/UnitTests.cs` (lines 783, 787, 798, 809, 820, 827, 840, 850, 863, 875, 1216, 1266). They
are a trap for anyone who reaches for them later. Within `Decrypt`, the "data found after final
chunk" branch at `:67-68` and the "payload ended without a final chunk" branch at `:73` are both
unreachable by construction: `NextChunk` sets `chunkLen = remaining` exactly when `isFinal`, so
`offset == inputData.Length` after the increment and the loop can only exit via the `isFinal` return.

**Reproduction — NOT REPRODUCED**, and there is no failing input, which is precisely the point.

*Correction to a common framing:* these methods do **not** violate `AgeEncrypt`'s class-level
memory-bounded guarantee (`Age/AgeEncrypt.cs:10-11`), because that guarantee covers `AgeEncrypt`'s
public streaming APIs and no public path reaches these. They are dead weight and a future trap, not a
live contradiction.

**Severity + who is affected** — **hygiene**; nobody today.

**API-neutral?** — Yes; `StreamEncryption` is an `internal static class`.

**Fix shape** — Delete both whole-stream methods and rewrite the tests to drive
`EncryptStream`/`DecryptStream`, or keep them, drop the unreachable branches, and document them as
test-only. `next-version` keeps a `StreamEncryption` but has no equivalent buffered pair.

**Confidence** — certain on the facts; lowest priority in the survey.

---

<a id="h9"></a>
### H9 — Armor decoder accepts a bare CR as a line terminator

**Location** — `Age/Format/AsciiArmor.cs:49` (the `StreamReader`) and
`Age/Format/DearmorStream.cs:86` (`_reader.ReadLine()`).

**What is wrong** — `StreamReader.ReadLine` treats a lone `\r` as a line terminator. go-age only
strips a trailing `\r` **after** a `\n` (`armor.go:97-98`: `ReadBytes('\n')` then
`TrimSuffix(line, "\n")` then `TrimSuffix(line, "\r")`, so a bare CR stays inside the line and fails
base64 decode), and rust-age explicitly errors (`primitives/armor.rs:858-863`,
`ArmoredReadError::LineContainsCr`). main is more permissive than both.

**Reproduction** — take a valid armored file and replace every `\n` with `\r`:

```
age  -d -i key.txt cr_only.age  -> reject
main -d -i key.txt cr_only.age  -> ACCEPT (decrypts)
```

The CRLF variant is accepted by both (correct). Nine other structural edge cases (blank line in body,
lowercase END marker, missing END marker, trailing junk, trailing whitespace, no trailing newline,
leading blank lines, trailing space in a body line) agree exactly with `age`.

**Severity + who is affected** — **hygiene.** Accept-more only: no valid file is rejected and no
user's data becomes unreadable. Strict-parsing gap, not a decryption failure.

**API-neutral?** — Yes.

**Fix shape** — Reject a body/marker line whose raw bytes were terminated by a bare CR — read lines
at the byte level in `NewlineBoundedStream`/`DearmorStream` and treat `\r` as valid only immediately
before `\n`. **`next-version` does not fix this either** (its `ArmorLineAccumulator` also accepts CR),
so there is no upstream commit to port. Lowest priority of the armor set; skip if the patch is being
kept tight.

**Confidence** — certain; reproduced.

---

<a id="h10"></a>
### H10 — Armor decoder accepts leading whitespace on the BEGIN marker

**Location** — `Age/Format/AsciiArmor.cs:66` — `if (line.TrimStart() != BeginMarker)`.

**What is wrong** — `"   -----BEGIN AGE ENCRYPTED FILE-----"` is accepted. go-age requires
`string(line) != Header` exactly (`armor.go:131`).

**Reproduction** — prefix a valid armored file with three spaces:

```
age  -d -i key.txt lead_spaces_marker.age  -> reject ("invalid first line")
main -d -i key.txt lead_spaces_marker.age  -> ACCEPT
```

**Severity + who is affected** — **hygiene**; accept-more only.

**API-neutral?** — Yes.

**Fix shape** — **Recommendation: leave it alone.** This looks deliberate, not accidental:
`AsciiArmor.IsArmored` (`:27-42`) has a matching `SkipLeadingWhitespace` byte loop so detection and
parsing agree, and `next-version` deliberately kept the same leniency
(`Age/Format/ArmorDecoder.cs:24`, `line.TrimStart().SequenceEqual(ArmorFormat.BeginMarker)`). This is
a design choice on record, not a defect to backport. Flagged only so the divergence is documented.
If strict parity with `age` ever becomes a goal, compare the line exactly and drop the
`SkipLeadingWhitespace` loop in the same change.

**Confidence** — certain; reproduced.

---

<a id="h11"></a>
### H11 — No bound on leading whitespace before the BEGIN marker

**Location** — `Age/Format/AsciiArmor.cs:58-61` —
`do { line = reader.ReadLine(); } while (line != null && line.AsSpan().Trim().Length == 0);`

**What is wrong** — The blank-line skip loop has no counter. go-age caps both leading and trailing
whitespace at 1024 bytes (`armor.go:102` trailing, `:125-127` `removedWhitespace > maxWhitespace`
leading).

**Reproduction** — prepend 200 MB of newlines to a valid armored file:

```
age  -d -i key.txt lb.age  -> 0.024 s
main -d -i key.txt lb.age  -> 1.97 s user CPU before it even reaches the marker
```

**Two corrections that both argue for keeping this at hygiene or lower.**
(1) In this reproduction `age` did **not** hit its 1024-byte cap — it failed with
`parsing age header: unexpected intro: "\n"`, i.e. the CLI saw a first byte that is not `-`, treated
the file as binary, and never entered the armor reader. The cap exists in go-age's `armor.Reader`,
but the repro does not exercise it, so the timing contrast is overstated.
(2) The cost is strictly **linear** in the prefix (1.97 s for 200 MB ≈ read throughput), with no
amplification and O(1) memory — `AgeLimits.MaxArmorLineBytes` (65536) still bounds any single line.
"Spins indefinitely" is only true for a genuinely unbounded stream, which is a property of the
caller's source rather than of this loop.

The trailing-whitespace side is **not** vulnerable: `DearmorStream.ValidateTrailing` (`:115-127`) is
bounded in practice by `NewlineBoundedStream` — 200 MB of trailing spaces trips
`armor line exceeds 65536 bytes` in 0.19 s.

**Severity + who is affected** — **hygiene.** Not exploitable as a DoS beyond "reading a large input
takes time". Worth fixing only for parity with go-age.

**API-neutral?** — Yes; a few lines inside a private helper.

**Fix shape** — Count bytes consumed by the blank-line skip and throw `AgeArmorException` past 1024,
matching go-age. `next-version` encodes this as `AsciiArmor.MaxLeadingWhitespace = 1024`
(`Age/Format/AsciiArmor.cs:7`) used to size the detection probe.

**Confidence** — certain; reproduced. Fix not built or tested.

---

## 4. Backport list (ordered by severity)

### Tier 1 — ship these

| # | Defect | One-line rationale |
|---|---|---|
| [S1](#s1) | Plugin CWD execution | Arbitrary code execution + file-key disclosure; spec-prohibited; both references refuse. |
| [S2](#s2)/[S3](#s3)/[C11](#c11) | `AgeRandomAccess` final-chunk authentication | One fix, three defects: silent acceptance of truncated ciphertext that `age` and main's own forward-only path both reject. |
| [C1](#c1) | Armor padded-final-line rejection | ~4.2% of valid armored files unreadable, including AgeSharp's own encrypted identity files. Fix built and fully verified. |
| [S4](#s4) | Double `Dispose` → `ArrayPool` double-Return | Cross-renter memory aliasing from idiomatic `using` code; also produces spurious auth failures. |
| [C4](#c4) | Plugin multi-stanza drop | Silent, permanent data loss with exit 0. |

### Tier 2 — clear defects, low risk

| # | Defect | Rationale |
|---|---|---|
| [S5](#s5) | Disposed identity → all-zero keypair | Silent fail-open to a world-known key; three-line guard. |
| [S6](#s6) | `extension-labels` advertised then ignored | One-line deletion; restores the PQ/classical mixing guardrail. |
| [C5](#c5) | Plugin FILE_INDEX per stanza | One-token change; main cannot decrypt files `age` decrypts. |
| [C6](#c6) | Plugin stderr deadlock | Hard hang with no timeout past 64 KiB of plugin diagnostics. |
| [C2](#c2) | Armor disposes the caller's stream | Violates the library's own documented invariant; fix built and verified. Call out the behaviour change. |
| [C3](#c3) | Culture-sensitive `StartsWith` | main accepts files both references reject, and disagrees with its own AOT build. |
| [C8](#c8)/[C9](#c9)/[C10](#c10) | Unguarded agreements + raw BCL exceptions | One shared `CryptoHelper.X25519Agree` helper covers most of it; stops "This is a bug" on merely-malformed input. |
| [C7](#c7) | Raw exceptions from the plugin path | Same class as above; `AgePluginException` already exists. |
| [C12](#c12) | `Read()` after `Dispose()` | Returns another renter's bytes as plaintext; free once [S4](#s4)'s `_disposed` field exists. |

### Tier 3 — zeroization cluster (defence in depth; ship together)

| # | Defect | Rationale |
|---|---|---|
| [S7](#s7) | PQ path zeroes nothing | `seedPq`/`seedT` are identity-equivalent; `Dispose` does not erase what it promises to. |
| [S8](#s8) | `HkdfDerive` ikm copy | Two uncleared file-key copies per operation, every recipient type. |
| [S9](#s9) | File key on `AgeEncrypt` error paths | Reachable from attacker-supplied truncated/tampered ciphertext. |
| [S10](#s10) | `AgeKeygen` identity-file plaintext | Raw private keys; array half is neutral, string half is not. |
| [S11](#s11) | `Ed25519Converter` SHA-512 expansion | Defeats `SshEd25519Identity.Dispose`; written fresh, not on `next-version`. |
| [S12](#s12) | `Bech32` 5-bit private key | Defeats the deliberate zeroing in both `Parse` methods; written fresh. |
| [H1](#h1) | `Header.ComputeMac` MAC key | Same one-line pattern; the last unguarded derived key. |
| [H4](#h4) | `X25519Identity.Unwrap` window | Free while the file is open; no reachable exposure — do not bill it as a vulnerability. |

### Tier 4 — interop and polish, take if the release is not being kept tight

| # | Defect | Rationale |
|---|---|---|
| [I4](#i4) | Plugin FILE_INDEX validation | Ship with [C5](#c5); meaningless before it. |
| [I5](#i5) | `confirm` with zero args | Two-line guard, both copies. |
| [I2](#i2) | PQ recipient not validated at parse | Recipients-file validators pass a file that then fails mid-encryption. |
| [I3](#i3) | scrypt cap 20 vs Go's 22 | Genuine Go-produced files are refused. Or keep 20 as policy and fix the docs. |
| [H7](#h7) | Plugin zombie + 5 s stall | Resource leak; `Kill` on timeout. |
| [H6](#h6) | PQ per-stanza keygen | ~6-7x pre-auth CPU vs `age`; part 1 (cache `Recipient`) lifts from `next-version`. |
| [H2](#h2)(a) | `ScryptRecipient` `finally` | Only the OOM path is reachable; cheap. |
| [H3](#h3) | Plugin base64 secret copies | Encode half is internal; leave `IPluginCallbacks` alone. |
| [H9](#h9), [H11](#h11) | Armor bare CR, unbounded leading whitespace | Parity with the references; neither breaks anything today. |
| [H8](#h8) | `StreamEncryption` dead methods | Delete or document; do not block a security patch on it. |

---

## 5. Do NOT backport

| Thing | Why not |
|---|---|
| `next-version`'s `IRecipient.Wrap` → `IReadOnlyList<Stanza>` (`fd16800`) | Public API break. Use the internal `IMultiStanzaRecipient` shape in [C4](#c4) instead. |
| `next-version`'s `HkdfDerive` → fill-a-`Span<byte>` (`30f38d1`) | Cascades into 22 call sites. Keep main's `byte[]` return; take only the `ikmCopy` `finally` ([S8](#s8)). |
| `next-version`'s `ScryptRecipient` → `Passphrase` type | New public type, new `ReadOnlySpan<char>` ctors, `IDisposable`, plus a rename. Take only part (a) of [H2](#h2). |
| `next-version`'s `IPluginCallbacks` split (`RequestSecret` returning `char[]`, `08facf6`) | Public interface change. Take only the internal `WriteStanza`/`Base64Unpadded` half ([H3](#h3)). |
| `next-version`'s `ParseIdentities(ReadOnlySpan<char>)` | `ParseIdentityFile(string, IPluginCallbacks)` is `PublicAPI.Shipped.txt:112`. Accept the residual string ([S10](#s10)). |
| `next-version`'s whole-cloth `DearmorStream`/`PeekableStream` rewrite | Entangled with the v0.3 sans-I/O redesign. Use the `leaveOpen` flag ([C2](#c2)) and, if wanted, port `PeekableStream` alone ([I1](#i1)). |
| `next-version`'s `SeekableDecryptStream` | Same — port the *behaviour* (eager final-chunk decrypt) into `AgeRandomAccess`, not the class. |
| [H10](#h10) — strict BEGIN-marker comparison | Deliberate, consistent with `IsArmored`'s own whitespace skip, and kept on `next-version`. Documented divergence, not a defect. |
| [H5](#h5) — zeroing the chunk on `DecryptChunkAt`'s throw | The abandoned array is zero-length. A no-op change; include only incidentally, never in release notes. |
| [I1](#i1) full non-seekable armor support | Widens accepted input in a patch release, against explicit XML docs. Ship the error-message fix instead, or defer to a minor. |

---

## 6. Considered and dismissed

**"`AgeRandomAccess.ReadAt` clears the decrypted plaintext chunk outside a `finally`"
(`Age/AgeRandomAccess.cs:98-104`) — REFUTED as a defect.** The literal observation is true —
`ZeroMemory(plaintext)` at `:104` is not in a `finally` — but no reachable path makes it matter, and
both cited triggers are wrong:

1. The `AgePayloadException` at `:181-182` is thrown **inside** `DecryptChunkAt`, before `plaintext`
   is returned, so `ReadAt`'s loop body never holds it and wrapping that loop would not cover the one
   case it names. That branch also only fires when `plaintext.Length == 0`.
2. The claimed out-of-range at `:102` is unreachable: `PlaintextLength` comes from
   `ComputePlaintextLength` (`:234-245`), which derives the final chunk's plaintext size from exactly
   the same layout arithmetic that `DecryptChunkAt` (`:167-179`) uses to size the chunk it decrypts,
   so `plaintext.Length - offsetInChunk` is always positive while `currentOffset < PlaintextLength`.
   The adjacent hazard (a zero `toCopy` spinning the `while` at `:96`) is unreachable for the same
   reason.
3. Nothing else in `DecryptChunkAt` can throw after `plaintext` exists — `ReadEncryptedChunk`
   (`:187-206`) and `StreamEncryption.DecryptChunk` both throw before it is allocated.
4. The secondary point ("plaintext-adjacent" per-call 64 KiB arrays in `ReadEncryptedChunk`) is
   affirmatively wrong: those hold **ciphertext**, which `CLAUDE.md` states is deliberately not
   zeroed.

At most an optional defensive tidy-up. Not a v0.2 patch entry. (This is separate from [H5](#h5),
which is the `DecryptChunkAt`-side version of the same non-issue.)

**Also explicitly checked and found NOT to be defects** (recorded so they are not re-investigated):

- **"The all-zero X25519 check is missing on main."** False, and it was the false positive that
  prompted this survey's method rules. All 8 `CalculateAgreement` sites were enumerated by grep:
  3 have AgeSharp's own guard, and BouncyCastle's `GenerateSecret` rejects an all-zero result at
  **all 8**. No zero shared secret ever reaches HKDF on main. `docs/spec/age.md:294`'s MUST is
  satisfied everywhere. The defects at the unguarded sites are exception-type defects only
  ([C8](#c8), [C9](#c9), [C10](#c10)).
- **Non-canonical X25519 public keys (value + p, high bit set) accepted by `Wrap`.** `age` v1.3.1
  accepts the same 5, verified by running it. Not a divergence.
- **scrypt-must-be-alone.** main is *stricter* than `age` v1.3.1 here (Go's check lives inside
  `ScryptIdentity.Unwrap`, which is never consulted for an X25519 identity) and main follows
  `docs/spec/age.md:334`. **Do not "fix" this.**
- **Bech32 casing.** main requires recipients lowercase and secret keys uppercase; Go enforces the
  same thing by a different route (`internal/bech32` returns the HRP with original case and `pq.go`
  compares exactly). Equivalent.
- **`AsciiArmor.Armor` (`Age/Format/AsciiArmor.cs:72-95`) is dead code.** No public API reaches it —
  the only production armor writer is `ArmorStream` via `AgeEncrypt.cs:167`; it is exercised only by
  `Age.Tests`. Its unchecked `Convert.TryToBase64Chars` return is therefore not a live defect, though
  the duplication is a divergence risk worth deleting.
- **`Header.ParseMacLine`'s `allRaw[..^macSuffix.Length]` slice.** Cannot underflow — the MAC line is
  always freshly read (`PushBack` is only used for `-> ` lines), so the raw buffer always ends with
  `" " + macB64 + "\n"`.
- **`SshRsaIdentity.Dispose` does not zero.** Deliberate and documented — BouncyCastle `BigInteger`
  fields cannot be zeroed. Accurate, not a defect.
- **`AgeRandomAccess.ReadAt` spinning.** `available` is provably > 0 for every offset below
  `PlaintextLength`.

---

## 7. Coverage and limits

### Verified clean (do not re-spend effort here)

**Cryptographic core — all derivations correct against `docs/spec/age.md`, checked line by line
*and* proven by two-way interop with `age` v1.3.1 on 100 KiB payloads:**
X25519 (`info="age-encryption.org/v1/X25519"`, `salt = ephShare‖recipient`); ssh-ed25519 tweak and
wrap-key salts (matching `agessh.go:217-231,329-338`); scrypt salt/N/r/p; payload key
`HKDF(fileKey, nonce, "payload")`; header MAC key `HKDF(fileKey, empty, "header")` with the HMAC over
the header through `---` excluding the trailing space. X-Wing combiner order, seed expansion, HPKE
suite ID `HPKE‖0x647a‖0x0001‖0x0003` and RFC 9180 §5.1 key schedule all verified — the spec's own PQ
vector (`docs/spec/age.md:186`) reproduces character-for-character.

**Payload/chunking layer.** 76 plaintext sizes (`k*65536 + {-17,-16,-15,-1,0,+1,+15,+16,+17}` for
k=0..5, 25 pseudorandom sizes, plus 5 MiB + 12345) round-tripped four ways each (main→`age`,
`age`→main, main→main, and the same two armored). All byte-exact, zero failures. The 11-byte
big-endian chunk counter plus final flag is proven interoperable to 80 chunks. The forward-only
decryptor's accept/reject verdict matched `age` on **every** case of a 7-size × 5-truncation sweep and
a 3-size × 4-junk-length trailing-data sweep. `EncryptStream`'s look-ahead-byte chunking never emits a
trailing empty chunk. Detached mode round-trips exactly at 0/65535/65536/65537/131072/131073.

**Header parsing.** Three differential campaigns against `age`: 17 hand-picked malformed headers
(agreement on all), 582 random byte-level mutations (582/582 rejected by both, zero disagreements),
800 structured framing mutants (zero cases where main accepted and `age` rejected). Every spec MUST
checked and enforced: canonical unpadded base64 everywhere (including the MAC line), printable-ASCII
args, body-line length rules, exact version-line match, MAC byte range, CR and non-ASCII rejection,
scrypt/X25519/mlkem arg counts and the partitioning-oracle body-length checks before decryption.
`AgeLimits.MaxHeaderLineBytes` (65536) and `MaxHeaderBytes` (16777216) verified exact — no off-by-one.
A 0..300-byte body-length sweep through a custom `IRecipient`, every file handed to `age -d`: all 301
accepted.

**Armor encoding.** main's `ArmorStream` output is structurally identical to `age -a` at every size
tested; `age -d` accepted all 201 of main's armored outputs over plaintext 0..200. Verified
insensitive to I/O granularity: 96 combinations of source dribble (1/7/48 bytes per `Read`) × caller
buffer (1/3/65/4096) × plaintext size. Armor **decoding** matches `age` on everything except
[C1](#c1) — a 400-case structural mutation fuzz found zero accept/reject disagreements once [C1](#c1)
is fixed.

**PQ decrypt path.** 4000 random 1-3 byte mutations across the whole header of a PQ-encrypted file,
through the public `AgeEncrypt.Decrypt`: zero non-`AgeException` escapes. The exception-leak defect
([C9](#c9)) is encrypt-side only.

**Plugin protocol.** `PluginNameValidator` matches the spec ABNF (stricter than go-age).
`WriteStanza` framing is byte-correct including the empty terminator for an exact multiple of 64.
Null-callbacks correctly answers `(fail)`. Unknown/grease phase-2 commands answered `unsupported`.
`done` with no stanza raises correctly. identity-v1 error handling matches the spec's response table.
Process count matches go-age (one per identity on decrypt, one per recipient on encrypt).

**Zeroing sites that are correct.** `DecryptStream`/`EncryptStream` `Dispose` zero the payload key and
the pooled plaintext buffer using `.AsSpan(0, size)` on the oversized rental, and `DecryptStream`
zeroes the residual tail when a chunk shrinks. `BouncyCastleAeadCipher` returns all three rentals with
`clearArray: true`, including `output` on the tag-mismatch path. All four classical
recipient/identity `Wrap`/`Unwrap` methods clear `wrapKey`/`sharedSecret`/`tweak`/`tweakedSS` in
genuine `finally` blocks. `X25519Identity`, `MlKem768X25519Identity` and `SshEd25519Identity`
`Dispose` implementations all zero and are idempotent. `AgeRandomAccess.Dispose` and
`InitializeFromStream` are both correct.

**Miscellaneous.** `string.Contains(string)` and `!=` on strings are ordinal by default, so
`SshKeyParser.cs:51` and `AsciiArmor.cs:66` are unaffected by [C3](#c3). `HeaderReader` does not
over-read into the payload. `Base64Unpadded` cannot be tricked by embedded whitespace.
`MlKem768X25519Identity.Unwrap` correctly relies on ML-KEM implicit rejection, matching
`pq.go:160-162`.

### Not examined

- **`SshRsa*` recipients and identities** were not audited at all.
- **`Age.Cli` argument handling and file I/O** beyond the `StartsWith` sites and the stdin buffering.
- **Chunk-counter overflow past 2^88 chunks** — not reachable.
- **Concurrent use of one `AgeRandomAccess` from multiple threads** — documented as unsupported.
- **Behaviour when the caller's stream contains data beyond the age file** — documented as
  unsupported, and `AgeRandomAccess`'s use of `Stream.Length` makes it structurally so.
- **`docs/`, benchmarks, packaging, CI.**

### Method limits the reader should weigh

- **main has NO async API.** `grep -rn "Async|await |Task<"` over `Age/` and `Age.Cli/` returns zero
  matches and `PublicAPI.Shipped.txt` has no `Task` entry. There is therefore **no sync/async
  divergence to hunt on main**, unlike `next-version`. `CopyToAsync` over a `DecryptReader` was
  verified byte-identical to the sync path; the only consequence of the BCL defaults is
  sync-over-async thread-pool blocking, which was not filed.
- **Heap-residue attribution is imperfect.** BouncyCastle's `HMac`/`Sha256Digest` block buffer retains
  any IKM ≤ 64 bytes, `MLKemPrivateKeyParameters.FromSeed` retains the seed, and the BCL AEAD retains
  its key. So "this exact array is the one in the dump" is not provable for those; what *is* proved is
  that the secret survives the operation, and that AgeSharp's own copy is uncleared is certain from
  reading. Several zeroization fixes therefore **reduce** rather than **eliminate** residue — say so
  in the changelog.
- **Heap-sweep technique.** Non-compacting blocking gen2 collections then ~520 MB of
  `GC.AllocateUninitializedArray<byte>(64 KiB)`, with needles pinned alive and two controls per run.
  An earlier attempt using a **compacting** collection inverted both controls — compaction moves live
  objects and leaves their bytes behind. Worth knowing if anyone re-runs this. A separate
  large-object-region-biased scan produced **false negatives** on small gen0 arrays; those negatives
  are inconclusive, not evidence of absence.
- **main already passes all 143 CCTV vectors and its 431-test suite.** Neither proves anything new;
  every finding above came from a size sweep, a differential run against `age`, a fake plugin, a heap
  probe, or code reading.
- **The main worktree was not modified.** All fixes were validated in copies
  (`.../scratchpad/fixwt`, `.../scratchpad/repro`, `.../scratchpad/leakprobe`,
  `.../scratchpad/pluginprobe-x7`, `.../scratchpad/harness`, `.../scratchpad/verify`).
  `git status --short` on `main-wt` is empty and it rebuilds with 0 warnings.

### Test-suite changes the backport requires

| File | Line | Change |
|---|---|---|
| `Age.Tests/PluginTests.cs` | 313 | Asserts `-> extension-labels` is sent — remove with [S6](#s6). |
| `Age.Tests/PluginTests.cs` | 542-543 | Asserts the buggy per-stanza FILE_INDEX wire form — update to index `0` on both, with [C5](#c5). |
| `Age.Tests/UnitTests.cs` | 783 ff. | Only callers of `StreamEncryption`'s whole-stream methods — rewrite if [H8](#h8) is taken. |

And two regression gaps that let defects ship: **no test anywhere asserts caller-stream ownership**
([C2](#c2)), **no test exercises double-`Dispose`** ([S4](#s4)), and
`Age.Tests/RandomAccessTests.cs` has **no truncation or tampering test at all**
([S2](#s2)/[S3](#s3)). Add all three.
