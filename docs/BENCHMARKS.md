# Benchmarks

Measured on Apple M2 (8 cores, 16 GB), macOS 27.2, .NET 10.0.0 (built with the .NET 11
SDK), BenchmarkDotNet 0.14.0, on 2026-11-19, against `main` at `0.2.0-preview.6`. The
previous run, on 2026-07-23 on the same machine, is within a few percent everywhere except
where noted below.

Memory is bounded: the stream-to-stream APIs (`Encrypt`, `Decrypt`, `EncryptDetached`,
`DecryptDetached`) stream chunk by chunk with pooled, fixed-size buffers, so a 1 GiB
file uses the same working set as a 1 MB one. The managed ChaCha20-Poly1305 backend used
in the browser (BouncyCastle) is 1.5–2× slower than the native one:

| Payload | Native | BouncyCastle | Ratio |
|---|---:|---:|---:|
| 64 KiB | 101 us | 202 us | 2.0× |
| 1 MiB | 1,672 us | 2,576 us | 1.5× |
| 16 MiB | 25.6 ms | 41.9 ms | 1.6× |

These come from a short run (three iterations), so expect a few percent of noise.

An earlier comparison of AgeSharp's command-line tool against `age` and `rage` was
removed with the tool; it is in the git history.

## BenchmarkDotNet Microbenchmarks

Run with `make bench`. These measure individual operations without
process startup overhead.

### Encrypt / Decrypt

| Operation | 1 KB | 64 KB | 1 MB |
|---|---:|---:|---:|
| Encrypt | 100 us | 209 us | 2,081 us |
| Decrypt | 97 us | 209 us | 2,043 us |
| Encrypt (armored) | 101 us | 236 us | 2,488 us |
| Decrypt (armored) | 103 us | 279 us | 3,196 us |

Throughput at 1 MB: ~505 MB/s encrypt, ~515 MB/s decrypt.
Armored adds ~15-55% overhead due to Base64 encoding/decoding. The
pre-auth parser bounds add one vectorized newline scan per buffered read
on the armored-decrypt path; the cost is within measurement noise.

Allocations at 1 KB are ~20 KB (Encrypt) / ~17 KB (Decrypt) — a small,
constant per-operation cost (cipher setup plus chunk scratch buffers
rented from `ArrayPool<byte>.Shared` and reused across chunks). At 1 MB,
most allocation is the output `MemoryStream`'s growth, not the crypto path.

### Key Generation

Both types defer part of the work, in opposite directions, so `Generate()` alone is
not a comparable number. X25519 does its keygen in `Generate()`; ML-KEM-768-X25519
fills a 32-byte seed there and runs the ML-KEM keygen on first access to `Recipient`
(cached thereafter). Measuring only `Generate()` reports post-quantum keygen as eight
times *faster* than X25519, which is backwards — it simply has not happened yet.

**Secret key to usable public key** — the comparable figure:

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 26.3 us | 2.0 KB |
| ML-KEM-768-X25519 | 86.8 us | 22.4 KB |

Post-quantum costs ~3.3x the time and ~11x the memory, which is the expected shape
for ML-KEM-768 against a curve operation.

**`Generate()` alone**, for reference — useful only when you are generating a secret
that will be stored and not immediately turned into a recipient:

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,936 ns | 856 B |
| ML-KEM-768-X25519 | 258 ns | 96 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 86 us | 6.6 KB |
| X25519 Unwrap | 85 us | 5.9 KB |
| ML-KEM-768-X25519 Wrap | 131 us | 38.3 KB |
| ML-KEM-768-X25519 Unwrap | 171 us | 58.1 KB |
| Tagged P-256 Wrap (`age1tag1…`) | 486 us | 11.8 KB |
| Tagged P-256 + ML-KEM-768 Wrap (`age1tagpq1…`) | 523 us | 40.3 KB |
| Scrypt Wrap | 1,799 us | 1,035 KB |
| Scrypt Unwrap | 1,793 us | 1,035 KB |

X25519 is the fastest at ~85 us. ML-KEM hybrid adds ~50-100% overhead
(still under 200 us); it allocates ~17% less than in July. Scrypt is intentionally
slow (~1.8 ms) due to the password-hashing work factor.

The tagged recipients are encryption-only, so only Wrap is measured (2026-11-21). Nearly all
of a Wrap is one P-256 exchange: an ephemeral key and its ECDH with the recipient's point. It
runs on the platform's `ECDiffieHellman`, which is constant-time, as go-age's P-256 is;
BouncyCastle's managed P-256, which is not, is kept only for the browser. The platform's
speed depends on the OS. Per exchange (`P256ExchangeBenchmarks`, GitHub's runners for Linux
and Windows):

| | BouncyCastle | Platform |
|---|---:|---:|
| macOS (this machine) | 254 us | 489 us |
| Linux x64 (OpenSSL) | 278 us | 121 us |
| Windows x64 (CNG) | 309 us | 1,547 us |

So a tagged Wrap is about twice as slow as before on macOS, five times on Windows, and twice as
fast on Linux, and allocates a twentieth as much. The cost is paid once per recipient per file:
it dominates a small file and disappears behind the payload from a few megabytes on.

### Large files

A 256 MiB file through every path, written to `Stream.Null` so the output buffer's growth
does not count (`LargeFileBenchmarks`; one warm-up, five iterations). Measured 2026-11-20 on
the machine above.

| Operation | Time | Allocated |
|---|---:|---:|
| Encrypt | 441 ms | 22 KB |
| Decrypt | 473 ms | 16 KB |
| Encrypt (armored) | 519 ms | 23 KB |
| Decrypt (armored) | 658 ms | 26 KB |
| Encrypt, pushed into `EncryptWriter` | 421–426 ms | 35 KB |
| Decrypt, pushed into `DecryptWriter` | 463–464 ms | 17 KB |
| Decrypt (armored), pushed into `DecryptWriter` | 611–613 ms | 19 KB |

The writer rows were measured later the same day, two runs each, fed by `CopyTo` in its
default 80 KiB pieces. In the same runs the reading forms took 427–438 ms (encrypt),
463–483 ms (decrypt) and 626–792 ms (armored decrypt; the 792 ms run was disturbed), so
pushing costs nothing over pulling.

What a call allocates does not grow with the file, armored decryption included. Before the
armor decoder read lines as bytes, armored decryption allocated a string for every 64-character
line: 861 MB of short-lived garbage for this file, and 751–800 ms.

### Random Access

4 KiB reads from a 1 MB file through the seekable stream `DecryptReader` returns for a seekable
binary file: 256 reads in order, then 256 at random positions (`RandomAccessBenchmarks`).
Measured 2026-11-20, two runs each.

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 1.81 ms | 0 |
| Random Read | 29.3–29.4 ms | 0 |

`AgeRandomAccess`, which this replaced, took 29.2–29.4 ms and 31.0–31.1 ms in the same runs, and
allocated 32 and 34 MB: it decrypted a whole 64 KiB chunk afresh for every 4 KiB read, into new
arrays. The seekable stream keeps the chunk it last decrypted and reuses pooled buffers, so
reading in order decrypts each chunk once, 16 times faster. A random read still decrypts one
chunk for almost every read; it is about 5% faster for the buffers alone.

## Reproducing

```sh
make bench
```
