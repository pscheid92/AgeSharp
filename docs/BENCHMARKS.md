# Benchmarks

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 22 ms | 23 ms |
| 1 KB | dec | 22 ms | 21 ms | 22 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 21 ms | 37 ms | 23 ms |
| 1 MB | enc | 25 ms | 24 ms | 25 ms |
| 1 MB | dec | 23 ms | 25 ms | 26 ms |
| 10 MB | enc | 37 ms | 48 ms | 43 ms |
| 10 MB | dec | 35 ms | 57 ms | 55 ms |
| 100 MB | enc | 168 ms | 304 ms | 224 ms |
| 100 MB | dec | 154 ms | 331 ms | 250 ms |

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
| 100 MB | enc | 465 ms | 359 ms | 263 ms |
| 100 MB | dec | 324 ms | 454 ms | 418 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~22-35 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 154-168 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (224-250 ms) now beats rage (304-331 ms) after
  switching to .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (263 ms) now beats both rage (359 ms)
  and Go (465 ms) after routing the push-encrypt path through `EncryptStream`
  + `ArmorStream` without any intermediate buffer.
- **Bounded memory**: all public push APIs (`Encrypt`, `Decrypt`,
  `EncryptDetached`, `DecryptDetached`) now stream chunk-by-chunk. Memory
  stays O(1) regardless of input size — a 1 GiB file uses the same working
  set as a 1 MB file.
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
| Encrypt | 98 us | 203 us | 2,098 us |
| Decrypt | 97 us | 213 us | 2,135 us |
| Encrypt (armored) | 99 us | 231 us | 2,448 us |
| Decrypt (armored) | 99 us | 293 us | 3,380 us |

Throughput at 1 MB: ~490 MB/s encrypt, ~480 MB/s decrypt.
Armored adds ~15-60% overhead due to Base64 encoding/decoding.

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
