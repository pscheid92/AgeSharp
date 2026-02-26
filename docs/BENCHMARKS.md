# Benchmarks

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2 Pro, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 28 ms | 29 ms | 30 ms |
| 1 KB | dec | 29 ms | 28 ms | 29 ms |
| 64 KB | enc | 29 ms | 29 ms | 30 ms |
| 64 KB | dec | 28 ms | 29 ms | 30 ms |
| 1 MB | enc | 31 ms | 33 ms | 34 ms |
| 1 MB | dec | 32 ms | 37 ms | 34 ms |
| 10 MB | enc | 52 ms | 83 ms | 90 ms |
| 10 MB | dec | 44 ms | 75 ms | 73 ms |
| 100 MB | enc | 278 ms | 532 ms | 431 ms |
| 100 MB | dec | 168 ms | 486 ms | 411 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 28 ms | 29 ms | 29 ms |
| 1 KB | dec | 28 ms | 28 ms | 30 ms |
| 64 KB | enc | 33 ms | 31 ms | 30 ms |
| 64 KB | dec | 29 ms | 28 ms | 29 ms |
| 1 MB | enc | 79 ms | 64 ms | 49 ms |
| 1 MB | dec | 34 ms | 34 ms | 36 ms |
| 10 MB | enc | 102 ms | 93 ms | 118 ms |
| 10 MB | dec | 90 ms | 110 ms | 86 ms |
| 100 MB | enc | 524 ms | 622 ms | 754 ms |
| 100 MB | dec | 365 ms | 616 ms | 591 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~28-34 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go leads at 168-278 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (411-431 ms) beats rage (486-532 ms).
- **Armored decrypt**: AgeSharp's streaming `DearmorStream` keeps it
  competitive with rage across all sizes.
- **Startup**: The AOT-compiled AgeSharp binary starts in ~28 ms,
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
| Encrypt | 97 us | 291 us | 3,378 us |
| Decrypt | 99 us | 287 us | 3,330 us |
| Encrypt (armored) | 100 us | 356 us | 4,706 us |

Throughput at 1 MB: ~300 MB/s for encrypt/decrypt.
Armored is ~30% slower due to Base64 encoding overhead.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,992 ns | 880 B |
| ML-KEM-768-X25519 | 253 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 86 us | 7.7 KB |
| X25519 Unwrap | 84 us | 7.1 KB |
| ML-KEM-768-X25519 Wrap | 138 us | 52.7 KB |
| ML-KEM-768-X25519 Unwrap | 182 us | 76.0 KB |
| Scrypt Wrap | 1,862 us | 1,036 KB |
| Scrypt Unwrap | 1,865 us | 1,036 KB |

X25519 is the fastest at ~85 us. ML-KEM hybrid adds ~60-100% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.9 ms) due to the
password-hashing work factor.

### Random Access

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 48.6 ms | 48.4 MB |
| Random Read | 52.0 ms | 51.6 MB |

Random reads are only ~7% slower than sequential thanks to the
chunk-based design.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
