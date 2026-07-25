# Benchmarks

Measured on Apple M2 (8 cores, 16 GB), macOS 26, .NET 10, on 2026-07-24.
Numbers are for the v0.3 API surface (one-chunk seekable `DecryptReader` cache, the
push writer `EncryptWriter`, and the async facades).

## CLI Comparison: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)

Wall-clock time for encrypt and decrypt at various file sizes, averaged
over 5 iterations. AOT-compiled binary. Includes process startup, key
parsing, header processing, and I/O.

All times in milliseconds (lower is better).

### Binary

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 21 ms | 23 ms |
| 1 KB | dec | 21 ms | 21 ms | 23 ms |
| 64 KB | enc | 22 ms | 22 ms | 26 ms |
| 64 KB | dec | 27 ms | 21 ms | 23 ms |
| 1 MB | enc | 23 ms | 24 ms | 25 ms |
| 1 MB | dec | 23 ms | 24 ms | 25 ms |
| 10 MB | enc | 37 ms | 49 ms | 43 ms |
| 10 MB | dec | 35 ms | 52 ms | 47 ms |
| 100 MB | enc | 167 ms | 291 ms | 224 ms |
| 100 MB | dec | 149 ms | 325 ms | 244 ms |

### ASCII Armor (-a)

| Size | Op | age (Go) | rage (Rust) | age-sharp (C#) |
|---|---|---:|---:|---:|
| 1 KB | enc | 21 ms | 21 ms | 24 ms |
| 1 KB | dec | 21 ms | 21 ms | 23 ms |
| 64 KB | enc | 22 ms | 22 ms | 23 ms |
| 64 KB | dec | 21 ms | 21 ms | 23 ms |
| 1 MB | enc | 26 ms | 25 ms | 25 ms |
| 1 MB | dec | 25 ms | 26 ms | 28 ms |
| 10 MB | enc | 71 ms | 57 ms | 48 ms |
| 10 MB | dec | 54 ms | 65 ms | 64 ms |
| 100 MB | enc | 479 ms | 372 ms | 273 ms |
| 100 MB | dec | 334 ms | 460 ms | 440 ms |

### Key Takeaways

- **Up to 1 MB**: all three implementations are within noise of each other
  (~20-27 ms), dominated by process startup overhead.
- **Binary 100 MB**: Go still leads at 149-167 ms thanks to assembly-optimized
  ChaCha20-Poly1305. AgeSharp (224-244 ms) beats rage (291-325 ms) using
  .NET's hardware-accelerated `ChaCha20Poly1305`.
- **Armored 100 MB encrypt**: AgeSharp (273 ms) beats both rage (372 ms)
  and Go (479 ms) — the push-encrypt path runs through `EncryptStream`
  + `ArmorStream` without any intermediate buffer.
- **Bounded memory**: all public push APIs (`Encrypt`, `Decrypt`,
  `EncryptDetached`, `DecryptDetached`, `EncryptWriter`) stream chunk-by-chunk with
  pooled, fixed-size scratch buffers — no per-chunk heap allocations. Memory
  stays O(1) regardless of input size; a 1 GiB file uses the same working set
  as a 1 MB file. This applies to the native ChaCha20-Poly1305 backend; the
  managed BouncyCastle backend used automatically in the browser is ~2×
  slower and allocates a small, constant amount per chunk.
- **Startup**: the AOT-compiled AgeSharp binary starts in ~22 ms,
  comparable to native Go and Rust binaries.

### Versions

| Tool | Version |
|---|---|
| age (Go) | v1.3.1 |
| rage (Rust) | v0.11.1 |
| age-sharp (C#) | v0.3 (`next-version`, AOT, .NET 10) |

## BenchmarkDotNet Microbenchmarks

Run with `make bench`. These measure individual operations without
process startup overhead. Default job, `[MemoryDiagnoser]`.

### Encrypt / Decrypt

| Operation | 1 KB | 64 KB | 1 MB |
|---|---:|---:|---:|
| Encrypt | 104 μs | 210 μs | 2,139 μs |
| Decrypt | 103 μs | 222 μs | 2,202 μs |
| Encrypt (armored) | 105 μs | 242 μs | 2,509 μs |
| Decrypt (armored) | 106 μs | 302 μs | 3,776 μs |

Throughput at 1 MB: ~490 MB/s encrypt, ~475 MB/s decrypt.
Armored adds ~15-70% overhead due to Base64 encoding/decoding.

Allocations at 1 KB are ~20 KB (Encrypt) / ~16 KB (Decrypt) — a small,
constant per-operation cost (cipher setup plus chunk scratch buffers
rented from `ArrayPool<byte>.Shared` and reused across chunks). At 1 MB,
most allocation is the output `MemoryStream`'s growth, not the crypto path.

### Key Generation

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 | 2,168 ns | 880 B |
| ML-KEM-768-X25519 | 272 ns | 88 B |

### Recipient Wrap / Unwrap

| Operation | Time | Allocated |
|---|---:|---:|
| X25519 Wrap | 90 μs | 6.6 KB |
| X25519 Unwrap | 90 μs | 5.8 KB |
| ML-KEM-768-X25519 Wrap | 140 μs | 46.6 KB |
| ML-KEM-768-X25519 Unwrap | 188 μs | 70.0 KB |
| Scrypt Wrap | 2,002 μs | 1,035 KB |
| Scrypt Unwrap | 1,924 μs | 1,035 KB |

X25519 is the fastest at ~90 μs. ML-KEM hybrid adds ~55-110% overhead
(still sub-200 μs). Scrypt is intentionally slow (~1.9 ms) due to the
password-hashing work factor.

### Random Access (`DecryptReader` over a seekable source)

Reading a 1 MB ciphertext (16 chunks). The one-chunk cache decrypts each
chunk once for in-order reads, and every path is now **zero-allocation** —
the plaintext buffer is rented once and reused, so no `Read` allocates.

| Operation | Time | Allocated |
|---|---:|---:|
| Sequential read (4 KB reads) | 1.92 ms | 0 B |
| Small sequential reads (64 B reads) | 1.96 ms | 0 B |
| Random read (256 scattered 4 KB reads) | 31.3 ms | 0 B |

Sequential and 64-byte reads cost the same ~1.9 ms — the cache means read
granularity no longer drives decrypt work (each of the 16 chunks is decrypted
once). Before the v0.3 cache, small-read consumers re-decrypted the containing
chunk on every `Read`: the same sequential scan measured ~30 ms with ~32 MB
allocated. Random reads (256 seeks landing in different chunks) are cache
misses by construction, so they scale with the number of distinct chunks
touched — still zero-allocation.

### Async overhead

`EncryptAsync`/`DecryptAsync` over in-memory streams, versus the synchronous
path. The async state machine and header prefill add no measurable cost.

| Operation | 64 KB | 1 MB |
|---|---:|---:|
| Encrypt (sync) | 238 μs | 2,177 μs |
| Encrypt (async) | 210 μs | 2,148 μs |
| Decrypt (sync) | 221 μs | 2,178 μs |
| Decrypt (async) | 224 μs | 2,185 μs |

Async and sync are within measurement noise of each other, with identical
allocations — the async paths reuse the sync CPU state machine and differ only
in how they fill/drain the underlying stream.

### Push vs. pull encryption (1 MB)

| Shape | Time | Allocated |
|---|---:|---:|
| One-shot `Encrypt` | 2,177 μs | 3,991 KB |
| Push `EncryptWriter` | 2,014 μs | 2,012 KB |
| Pull `EncryptReader` | 2,193 μs | 3,991 KB |

All three run the same chunked STREAM path at ~2 ms. `EncryptWriter` allocates
~2 MB less and is ~7% faster here because the caller writes plaintext straight
into it — the one-shot and pull shapes each wrap the plaintext in an input
`MemoryStream` first, copying it.

## Reproducing

```sh
# CLI comparison (requires age and rage installed)
./scripts/bench_compare.sh

# BenchmarkDotNet microbenchmarks
make bench
```
