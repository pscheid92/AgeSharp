# Benchmarks

Measured on Apple M2 (8 cores, 16 GB), macOS 26, .NET 10, on 2026-07-23.
Numbers are refreshed against `main` at the current release (includes the
`IAeadCipher` backend seam and the pre-authentication parser bounds).

Memory is bounded: the push APIs (`Encrypt`, `Decrypt`, `EncryptDetached`,
`DecryptDetached`) stream chunk by chunk with pooled, fixed-size buffers, so a 1 GiB
file uses the same working set as a 1 MB one. The managed ChaCha20-Poly1305 backend used
in the browser is about 2× slower than the native one.

An earlier comparison of AgeSharp's command-line tool against `age` and `rage` was
removed with the tool; it is in the git history.

## BenchmarkDotNet Microbenchmarks

Run with `make bench`. These measure individual operations without
process startup overhead.

### Encrypt / Decrypt

| Operation | 1 KB | 64 KB | 1 MB |
|---|---:|---:|---:|
| Encrypt | 102 us | 204 us | 2,092 us |
| Decrypt | 101 us | 215 us | 2,118 us |
| Encrypt (armored) | 102 us | 235 us | 2,485 us |
| Decrypt (armored) | 108 us | 294 us | 3,382 us |

Throughput at 1 MB: ~500 MB/s encrypt, ~495 MB/s decrypt.
Armored adds ~15-60% overhead due to Base64 encoding/decoding. The
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
| X25519 | 28.6 us | 2.1 KB |
| ML-KEM-768-X25519 | 91.3 us | 28.5 KB |

Post-quantum costs ~3.2x the time and ~14x the memory, which is the expected shape
for ML-KEM-768 against a curve operation.

**`Generate()` alone**, for reference — useful only when you are generating a secret
that will be stored and not immediately turned into a recipient:

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 2,150 ns | 880 B |
| ML-KEM-768-X25519 | 275 ns | 96 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 89 us | 6.6 KB |
| X25519 Unwrap | 88 us | 5.8 KB |
| ML-KEM-768-X25519 Wrap | 137 us | 46.6 KB |
| ML-KEM-768-X25519 Unwrap | 182 us | 70.0 KB |
| Scrypt Wrap | 1,858 us | 1,035 KB |
| Scrypt Unwrap | 1,857 us | 1,035 KB |

X25519 is the fastest at ~88 us. ML-KEM hybrid adds ~55-105% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.9 ms) due to the
password-hashing work factor.

### Random Access

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 30.2 ms | 32.0 MB |
| Random Read | 32.1 ms | 34.2 MB |

Random reads are only ~6% slower than sequential thanks to the
chunk-based design.

## Reproducing

```sh
make bench
```
