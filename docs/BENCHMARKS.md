# Benchmarks

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 22 ms | 21 ms | 23 ms |
| 1 KB | dec | 22 ms | 21 ms | 23 ms |
| 64 KB | enc | 23 ms | 24 ms | 25 ms |
| 64 KB | dec | 22 ms | 22 ms | 23 ms |
| 1 MB | enc | 24 ms | 24 ms | 27 ms |
| 1 MB | dec | 25 ms | 31 ms | 30 ms |
| 10 MB | enc | 39 ms | 57 ms | 57 ms |
| 10 MB | dec | 38 ms | 56 ms | 52 ms |
| 100 MB | enc | 174 ms | 305 ms | 278 ms |
| 100 MB | dec | 149 ms | 328 ms | 276 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 23 ms | 29 ms | 24 ms |
| 1 KB | dec | 23 ms | 23 ms | 24 ms |
| 64 KB | enc | 24 ms | 26 ms | 29 ms |
| 64 KB | dec | 25 ms | 25 ms | 24 ms |
| 1 MB | enc | 29 ms | 27 ms | 28 ms |
| 1 MB | dec | 28 ms | 27 ms | 28 ms |
| 10 MB | enc | 70 ms | 70 ms | 110 ms |
| 10 MB | dec | 67 ms | 155 ms | 75 ms |
| 100 MB | enc | 480 ms | 380 ms | 490 ms |
| 100 MB | dec | 363 ms | 498 ms | 519 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~22-30 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 149-174 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (276-278 ms) now beats rage (305-328 ms) after
  switching to .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored decrypt**: AgeSharp's streaming `DearmorStream` keeps it
  competitive with rage across all sizes.
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
| Encrypt | 99 us | 201 us | 2,026 us |
| Decrypt | 99 us | 216 us | 2,179 us |
| Encrypt (armored) | 100 us | 262 us | 2,788 us |
| Decrypt (armored) | 99 us | 300 us | 3,816 us |

Throughput at 1 MB: ~495 MB/s encrypt, ~460 MB/s decrypt.
Armored adds ~30-75% overhead due to Base64 encoding/decoding.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,986 ns | 880 B |
| ML-KEM-768-X25519 | 255 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 87 us | 3.6 KB |
| X25519 Unwrap | 86 us | 2.9 KB |
| ML-KEM-768-X25519 Wrap | 137 us | 46.4 KB |
| ML-KEM-768-X25519 Unwrap | 183 us | 69.9 KB |
| Scrypt Wrap | 1,892 us | 1,035 KB |
| Scrypt Unwrap | 1,895 us | 1,035 KB |

X25519 is the fastest at ~86 us. ML-KEM hybrid adds ~60-100% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.9 ms) due to the
password-hashing work factor.

### Random Access

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 30.7 ms | 32.0 MB |
| Random Read | 34.2 ms | 34.2 MB |

Random reads are only ~11% slower than sequential thanks to the
chunk-based design.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
