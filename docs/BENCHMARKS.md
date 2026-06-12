# Benchmarks

Last updated: 2026-06-12 (Apple M2, .NET 10).

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 24 ms | 21 ms | 22 ms |
| 1 KB | dec | 21 ms | 21 ms | 22 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 21 ms | 21 ms | 22 ms |
| 1 MB | enc | 23 ms | 25 ms | 25 ms |
| 1 MB | dec | 23 ms | 24 ms | 25 ms |
| 10 MB | enc | 36 ms | 48 ms | 42 ms |
| 10 MB | dec | 34 ms | 51 ms | 47 ms |
| 100 MB | enc | 162 ms | 279 ms | 213 ms |
| 100 MB | dec | 144 ms | 316 ms | 246 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 21 ms | 22 ms |
| 1 KB | dec | 21 ms | 21 ms | 22 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 21 ms | 21 ms | 22 ms |
| 1 MB | enc | 26 ms | 24 ms | 24 ms |
| 1 MB | dec | 24 ms | 25 ms | 26 ms |
| 10 MB | enc | 69 ms | 55 ms | 45 ms |
| 10 MB | dec | 52 ms | 63 ms | 58 ms |
| 100 MB | enc | 460 ms | 357 ms | 251 ms |
| 100 MB | dec | 327 ms | 454 ms | 393 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~20-26 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 144-162 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (213-246 ms) beats rage (279-316 ms) after
  switching to .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (251 ms) beats both rage (357 ms)
  and Go (460 ms) after routing the push-encrypt path through `EncryptStream`
  + `ArmorStream` without any intermediate buffer.
- **Bounded memory**: all public push APIs (`Encrypt`, `Decrypt`,
  `EncryptDetached`, `DecryptDetached`) stream chunk-by-chunk with pooled,
  fixed-size scratch buffers — no per-chunk heap allocations. Memory stays
  O(1) regardless of input size; a 1 GiB file uses the same working set
  as a 1 MB file.
- **Hostile-input bounds are free**: header and armor parsing cap line and
  header sizes to prevent pre-authentication memory exhaustion. The armor
  bound is enforced with one vectorized scan per buffered read, so armored
  decrypt stays within measurement noise of the unbounded implementation.
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
| Encrypt | 102 us | 200 us | 2,058 us |
| Decrypt | 99 us | 213 us | 2,080 us |
| Encrypt (armored) | 100 us | 229 us | 2,357 us |
| Decrypt (armored) | 102 us | 284 us | 3,265 us |

Throughput at 1 MB: ~510 MB/s encrypt, ~500 MB/s decrypt.
Armored adds ~15-60% overhead due to Base64 encoding/decoding.

Allocations at 1 KB are ~20 KB (Encrypt) / ~17 KB (Decrypt) — chunk
scratch buffers are rented from `ArrayPool<byte>.Shared` and reused
across operations. At 1 MB, most allocation is the output
`MemoryStream`'s growth, not the crypto path.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,917 ns | 880 B |
| ML-KEM-768-X25519 | 251 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 87 us | 6.5 KB |
| X25519 Unwrap | 86 us | 5.7 KB |
| ML-KEM-768-X25519 Wrap | 133 us | 46.5 KB |
| ML-KEM-768-X25519 Unwrap | 178 us | 70.3 KB |
| Scrypt Wrap | 1,816 us | 1,035 KB |
| Scrypt Unwrap | 1,785 us | 1,035 KB |

X25519 is the fastest at ~86-87 us. ML-KEM hybrid adds ~50-105% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.8 ms) due to the
password-hashing work factor.

### Random Access

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 29.2 ms | 32.0 MB |
| Random Read | 30.9 ms | 34.2 MB |

Random reads are only ~6% slower than sequential thanks to the
chunk-based design.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
