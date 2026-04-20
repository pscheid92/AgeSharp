# Benchmarks

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. Measured on Apple M2, .NET 10, AOT-compiled binary.
Includes process startup, key parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 20 ms | 22 ms |
| 1 KB | dec | 21 ms | 20 ms | 21 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 21 ms | 21 ms | 22 ms |
| 1 MB | enc | 22 ms | 23 ms | 24 ms |
| 1 MB | dec | 22 ms | 23 ms | 25 ms |
| 10 MB | enc | 34 ms | 47 ms | 41 ms |
| 10 MB | dec | 34 ms | 51 ms | 46 ms |
| 100 MB | enc | 155 ms | 285 ms | 211 ms |
| 100 MB | dec | 144 ms | 324 ms | 242 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 20 ms | 22 ms |
| 1 KB | dec | 21 ms | 20 ms | 21 ms |
| 64 KB | enc | 21 ms | 21 ms | 22 ms |
| 64 KB | dec | 21 ms | 22 ms | 22 ms |
| 1 MB | enc | 25 ms | 24 ms | 24 ms |
| 1 MB | dec | 24 ms | 25 ms | 26 ms |
| 10 MB | enc | 67 ms | 55 ms | 45 ms |
| 10 MB | dec | 51 ms | 64 ms | 59 ms |
| 100 MB | enc | 436 ms | 359 ms | 251 ms |
| 100 MB | dec | 319 ms | 450 ms | 383 ms |

### Key Takeaways

- **Up to 1 MB**: All three implementations are within noise of each other
  (~20-26 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 144-155 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (211-242 ms) beats rage (285-324 ms) after
  switching to .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (251 ms) now beats both rage (359 ms)
  and Go (436 ms) after routing the push-encrypt path through `EncryptStream`
  + `ArmorStream` without any intermediate buffer.
- **Bounded memory**: all public push APIs (`Encrypt`, `Decrypt`,
  `EncryptDetached`, `DecryptDetached`) stream chunk-by-chunk with pooled,
  fixed-size scratch buffers — no per-chunk heap allocations. Memory stays
  O(1) regardless of input size; a 1 GiB file uses the same working set
  as a 1 MB file.
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
| Encrypt | 98 us | 195 us | 2,038 us |
| Decrypt | 95 us | 206 us | 2,088 us |
| Encrypt (armored) | 99 us | 223 us | 2,349 us |
| Decrypt (armored) | 99 us | 281 us | 3,309 us |

Throughput at 1 MB: ~500 MB/s encrypt, ~490 MB/s decrypt.
Armored adds ~15-60% overhead due to Base64 encoding/decoding.

Allocations at 1 KB are ~12 KB (Encrypt) / ~9 KB (Decrypt) — chunk
scratch buffers are rented from `ArrayPool<byte>.Shared` and reused
across operations. At 1 MB, most allocation is the output
`MemoryStream`'s growth, not the crypto path.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 1,919 ns | 880 B |
| ML-KEM-768-X25519 | 246 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 87 us | 3.6 KB |
| X25519 Unwrap | 84 us | 2.9 KB |
| ML-KEM-768-X25519 Wrap | 132 us | 46.7 KB |
| ML-KEM-768-X25519 Unwrap | 174 us | 69.9 KB |
| Scrypt Wrap | 1,785 us | 1,035 KB |
| Scrypt Unwrap | 1,778 us | 1,035 KB |

X25519 is the fastest at ~85 us. ML-KEM hybrid adds ~60-100% overhead
(still sub-200 us). Scrypt is intentionally slow (~1.8 ms) due to the
password-hashing work factor.

### Random Access

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential Read | 29.7 ms | 32.0 MB |
| Random Read | 31.5 ms | 34.2 MB |

Random reads are only ~6% slower than sequential thanks to the
chunk-based design.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
