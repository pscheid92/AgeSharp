# Benchmarks

Measured on Apple M2 (8 cores, 16 GB), macOS 26, .NET 10, on 2026-07-23.
Numbers are refreshed against `main` at the current release (includes the
`IAeadCipher` backend seam and the pre-authentication parser bounds).

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. AOT-compiled binary. Includes process startup, key
parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 21 ms | 22 ms |
| 1 KB | dec | 20 ms | 22 ms | 22 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 20 ms | 21 ms | 22 ms |
| 1 MB | enc | 23 ms | 24 ms | 25 ms |
| 1 MB | dec | 22 ms | 24 ms | 25 ms |
| 10 MB | enc | 37 ms | 49 ms | 44 ms |
| 10 MB | dec | 35 ms | 52 ms | 47 ms |
| 100 MB | enc | 173 ms | 298 ms | 222 ms |
| 100 MB | dec | 147 ms | 323 ms | 244 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 20 ms | 22 ms |
| 1 KB | dec | 20 ms | 20 ms | 22 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 21 ms | 21 ms | 22 ms |
| 1 MB | enc | 27 ms | 24 ms | 25 ms |
| 1 MB | dec | 24 ms | 25 ms | 26 ms |
| 10 MB | enc | 72 ms | 56 ms | 46 ms |
| 10 MB | dec | 53 ms | 64 ms | 60 ms |
| 100 MB | enc | 456 ms | 366 ms | 275 ms |
| 100 MB | dec | 325 ms | 449 ms | 409 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~20-27 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 147-173 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (222-244 ms) beats rage (298-323 ms) using
  .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (275 ms) beats both rage (366 ms)
  and Go (456 ms) — the push-encrypt path runs through `EncryptStream`
  + `ArmorStream` without any intermediate buffer.
- **Bounded memory**: all public push APIs (`Encrypt`, `Decrypt`,
  `EncryptDetached`, `DecryptDetached`) stream chunk-by-chunk with pooled,
  fixed-size scratch buffers — no per-chunk heap allocations. Memory stays
  O(1) regardless of input size; a 1 GiB file uses the same working set
  as a 1 MB file. This applies to the native ChaCha20-Poly1305 backend; the
  managed BouncyCastle backend used automatically in the browser is ~2×
  slower and allocates a small, constant amount per chunk.
- **Startup**: The AOT-compiled AgeSharp binary starts in ~21 ms,
  comparable to native Go and Rust binaries.

### Versions

| Tool | Version |
|---|---|
| age (Go) | v1.3.1 |
| rage (Rust) | v0.11.1 |
| age-sharp (C#) | main (AOT, .NET 10) |

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
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
