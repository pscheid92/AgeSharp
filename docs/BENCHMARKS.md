# Benchmarks

Measured on Apple M2 (8 cores, 16 GB), macOS 26, .NET 10, on 2026-07-23.

> **⚠️ Refresh pending for v0.3.** The numbers below were measured against the
> pre-v0.3 `main` (the `IAeadCipher` backend seam + pre-auth parser bounds). The
> v0.3 API adds a one-chunk cache to seekable `OpenRead` (#31) and a full async
> surface (#34), which change the random-access numbers in particular — the
> **Random Access** table's per-read allocations reflect the *old* re-decrypt-per-`Read`
> behavior and will drop sharply once re-measured. New `Async`, `PushPull`, and
> small-read cache benchmarks (see [Reproducing](#reproducing)) have been added but
> not yet measured. Run `make bench` on a quiet machine before the release tag and
> replace the tables below.

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

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,982 ns | 880 B |
| ML-KEM-768-X25519 | 251 ns | 88 B |

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

### v0.3 surface (pending measurement)

Three benchmark groups were added for the v0.3 API. Numbers land with the next
clean `make bench` run:

- **`AsyncBenchmarks`** — `Encrypt`/`Decrypt` sync vs `EncryptAsync`/`DecryptAsync`
  over in-memory streams, isolating the async state-machine + header-prefill
  overhead from any real I/O latency.
- **`PushPullBenchmarks`** — the three encryption shapes over the same plaintext:
  one-shot `Encrypt`, push `OpenWrite`, and pull `EncryptReader`. All run the same
  chunked STREAM path, so the delta is per-shape buffering.
- **`RandomAccessBenchmarks.SmallSequentialReads`** — 64-byte reads across the whole
  plaintext. With the one-chunk cache each 64 KiB chunk decrypts once regardless of
  how many small reads land in it; before the cache this re-decrypted per `Read`.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
