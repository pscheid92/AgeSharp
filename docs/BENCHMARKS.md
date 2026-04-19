# Benchmarks

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 23 ms | 22 ms | 23 ms |
| 1 KB | dec | 23 ms | 22 ms | 23 ms |
| 64 KB | enc | 22 ms | 22 ms | 23 ms |
| 64 KB | dec | 22 ms | 22 ms | 29 ms |
| 1 MB | enc | 25 ms | 24 ms | 26 ms |
| 1 MB | dec | 23 ms | 26 ms | 26 ms |
| 10 MB | enc | 37 ms | 49 ms | 48 ms |
| 10 MB | dec | 36 ms | 53 ms | 48 ms |
| 100 MB | enc | 161 ms | 287 ms | 242 ms |
| 100 MB | dec | 148 ms | 329 ms | 259 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 22 ms | 22 ms | 23 ms |
| 1 KB | dec | 22 ms | 22 ms | 23 ms |
| 64 KB | enc | 22 ms | 23 ms | 24 ms |
| 64 KB | dec | 23 ms | 22 ms | 23 ms |
| 1 MB | enc | 27 ms | 25 ms | 27 ms |
| 1 MB | dec | 25 ms | 26 ms | 27 ms |
| 10 MB | enc | 69 ms | 58 ms | 62 ms |
| 10 MB | dec | 53 ms | 65 ms | 63 ms |
| 100 MB | enc | 449 ms | 365 ms | 363 ms |
| 100 MB | dec | 330 ms | 461 ms | 453 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~22-30 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 148-161 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (242-259 ms) now beats rage (287-329 ms) after
  switching to .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (363 ms) now ties rage (365 ms) and
  beats Go (449 ms) after switching the armor path to stream ciphertext
  directly into `AsciiArmor.Armor` without an intermediate buffer.
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
| Encrypt | 97 us | 200 us | 1,990 us |
| Decrypt | 96 us | 210 us | 2,194 us |
| Encrypt (armored) | 99 us | 251 us | 2,656 us |
| Decrypt (armored) | 100 us | 286 us | 3,761 us |

Throughput at 1 MB: ~500 MB/s encrypt, ~455 MB/s decrypt.
Armored adds ~30-70% overhead due to Base64 encoding/decoding.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,974 ns | 880 B |
| ML-KEM-768-X25519 | 251 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 87 us | 3.6 KB |
| X25519 Unwrap | 85 us | 2.9 KB |
| ML-KEM-768-X25519 Wrap | 137 us | 46.5 KB |
| ML-KEM-768-X25519 Unwrap | 179 us | 69.9 KB |
| Scrypt Wrap | 1,833 us | 1,035 KB |
| Scrypt Unwrap | 1,833 us | 1,035 KB |

X25519 is the fastest at ~85 us. ML-KEM hybrid adds ~60-100% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.8 ms) due to the
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
