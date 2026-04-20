# Benchmarks

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 22 ms | 22 ms | 25 ms |
| 1 KB | dec | 24 ms | 32 ms | 36 ms |
| 64 KB | enc | 31 ms | 32 ms | 24 ms |
| 64 KB | dec | 23 ms | 22 ms | 23 ms |
| 1 MB | enc | 24 ms | 27 ms | 26 ms |
| 1 MB | dec | 38 ms | 30 ms | 32 ms |
| 10 MB | enc | 39 ms | 49 ms | 45 ms |
| 10 MB | dec | 35 ms | 56 ms | 50 ms |
| 100 MB | enc | 164 ms | 290 ms | 216 ms |
| 100 MB | dec | 148 ms | 331 ms | 247 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 29 ms | 22 ms | 26 ms |
| 1 KB | dec | 23 ms | 21 ms | 29 ms |
| 64 KB | enc | 24 ms | 28 ms | 25 ms |
| 64 KB | dec | 27 ms | 33 ms | 35 ms |
| 1 MB | enc | 34 ms | 33 ms | 29 ms |
| 1 MB | dec | 30 ms | 34 ms | 31 ms |
| 10 MB | enc | 74 ms | 59 ms | 50 ms |
| 10 MB | dec | 55 ms | 68 ms | 62 ms |
| 100 MB | enc | 456 ms | 366 ms | 258 ms |
| 100 MB | dec | 329 ms | 461 ms | 395 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~22-38 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 148-164 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (216-247 ms) now beats rage (290-331 ms) after
  switching to .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (258 ms) now beats both rage (366 ms)
  and Go (456 ms) after routing the push-encrypt path through `EncryptStream`
  + `ArmorStream` without any intermediate buffer.
- **Bounded memory**: all public push APIs (`Encrypt`, `Decrypt`,
  `EncryptDetached`, `DecryptDetached`) now stream chunk-by-chunk with
  fixed-size scratch buffers — no per-chunk heap allocations. Memory stays
  O(1) regardless of input size; a 1 GiB file uses the same working set
  as a 1 MB file.
- **Startup**: The AOT-compiled AgeSharp binary starts in ~22 ms,
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
| Encrypt | 101 us | 204 us | 2,087 us |
| Decrypt | 99 us | 215 us | 2,122 us |
| Encrypt (armored) | 102 us | 233 us | 2,438 us |
| Decrypt (armored) | 102 us | 290 us | 3,365 us |

Throughput at 1 MB: ~490 MB/s encrypt, ~480 MB/s decrypt.
Armored adds ~15-60% overhead due to Base64 encoding/decoding.

At 1 MB, `Encrypt`/`Decrypt` allocate ~4 MB / ~2 MB respectively —
a roughly 20-30% drop from pre-zero-alloc numbers thanks to reusing
a single scratch buffer across all chunks in the stream.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,979 ns | 880 B |
| ML-KEM-768-X25519 | 255 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 87 us | 3.6 KB |
| X25519 Unwrap | 84 us | 2.9 KB |
| ML-KEM-768-X25519 Wrap | 137 us | 46.7 KB |
| ML-KEM-768-X25519 Unwrap | 180 us | 69.9 KB |
| Scrypt Wrap | 1,839 us | 1,035 KB |
| Scrypt Unwrap | 1,963 us | 1,035 KB |

X25519 is the fastest at ~85 us. ML-KEM hybrid adds ~60-100% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.9 ms) due to the
password-hashing work factor.

### Random Access

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 30.1 ms | 32.0 MB |
| Random Read | 31.9 ms | 34.2 MB |

Random reads are only ~6% slower than sequential thanks to the
chunk-based design.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
