#!/usr/bin/env bash
set -euo pipefail

# CLI Benchmark: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)
# Measures wall-clock time for encrypt and decrypt at various file sizes.
# Compares both binary and ASCII-armored modes.

AGE="age"
RAGE="rage"
AGE_SHARP="./dist/age-sharp"

ITERATIONS=5
SIZES_KB=(1 64 1024 10240 102400)  # 1KB, 64KB, 1MB, 10MB, 100MB

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generate a key for each tool (all use the same X25519 format)
age-keygen -o "$TMPDIR/key.txt" 2>/dev/null
RECIPIENT=$(grep 'public key:' "$TMPDIR/key.txt" | awk '{print $NF}')

printf "CLI Benchmark: age (Go) vs rage (Rust) vs age-sharp (C#/.NET)\n"
printf "Iterations: %d per operation\n" "$ITERATIONS"
printf "Key type: X25519\n"
printf "Machine: %s\n" "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"

# Warm up each binary once
echo "Warming up..."
dd if=/dev/urandom of="$TMPDIR/warmup" bs=1024 count=1 2>/dev/null
for tool in "$AGE" "$RAGE" "$AGE_SHARP"; do
    $tool -r "$RECIPIENT" -o "$TMPDIR/warmup.age" "$TMPDIR/warmup" 2>/dev/null
    $tool -d -i "$TMPDIR/key.txt" -o /dev/null "$TMPDIR/warmup.age" 2>/dev/null
done
rm -f "$TMPDIR/warmup" "$TMPDIR/warmup.age"

bench_op() {
    local tool="$1" op="$2" input="$3" output="$4" key_file="$5" recipient="$6" iterations="$7" armor="$8"

    local total=0
    for ((i = 0; i < iterations; i++)); do
        if [ "$op" = "encrypt" ]; then
            local start end elapsed
            start=$(python3 -c 'import time; print(time.perf_counter())')
            if [ "$armor" = "yes" ]; then
                $tool -a -r "$recipient" -o "$output" "$input" 2>/dev/null
            else
                $tool -r "$recipient" -o "$output" "$input" 2>/dev/null
            fi
            end=$(python3 -c 'import time; print(time.perf_counter())')
        else
            local start end elapsed
            start=$(python3 -c 'import time; print(time.perf_counter())')
            $tool -d -i "$key_file" -o /dev/null "$output" 2>/dev/null
            end=$(python3 -c 'import time; print(time.perf_counter())')
        fi
        elapsed=$(python3 -c "print(${end} - ${start})")
        total=$(python3 -c "print(${total} + ${elapsed})")
    done

    python3 -c "print(f'{${total} / ${iterations} * 1000:.2f}')"
}

format_label() {
    local size_kb="$1"
    if [ "$size_kb" -ge 1024 ]; then
        echo "$((size_kb / 1024)) MB"
    else
        echo "${size_kb} KB"
    fi
}

run_suite() {
    local mode="$1" armor="$2"

    printf "\n## %s\n\n" "$mode"
    printf "%-10s | %-6s | %-14s | %-14s | %-14s\n" "Size" "Op" "age (Go)" "rage (Rust)" "age-sharp (C#)"
    printf "%-10s-+-%-6s-+-%-14s-+-%-14s-+-%-14s\n" "----------" "------" "--------------" "--------------" "--------------"

    for size_kb in "${SIZES_KB[@]}"; do
        dd if=/dev/urandom of="$TMPDIR/plain" bs=1024 count="$size_kb" 2>/dev/null
        local label
        label=$(format_label "$size_kb")

        # Encrypt
        t_age=$(bench_op "$AGE" encrypt "$TMPDIR/plain" "$TMPDIR/enc_age" "$TMPDIR/key.txt" "$RECIPIENT" "$ITERATIONS" "$armor")
        t_rage=$(bench_op "$RAGE" encrypt "$TMPDIR/plain" "$TMPDIR/enc_rage" "$TMPDIR/key.txt" "$RECIPIENT" "$ITERATIONS" "$armor")
        t_sharp=$(bench_op "$AGE_SHARP" encrypt "$TMPDIR/plain" "$TMPDIR/enc_sharp" "$TMPDIR/key.txt" "$RECIPIENT" "$ITERATIONS" "$armor")
        printf "%-10s | %-6s | %11s ms | %11s ms | %11s ms\n" "$label" "enc" "$t_age" "$t_rage" "$t_sharp"

        # Decrypt (each tool decrypts its own ciphertext)
        t_age=$(bench_op "$AGE" decrypt "$TMPDIR/plain" "$TMPDIR/enc_age" "$TMPDIR/key.txt" "$RECIPIENT" "$ITERATIONS" "$armor")
        t_rage=$(bench_op "$RAGE" decrypt "$TMPDIR/plain" "$TMPDIR/enc_rage" "$TMPDIR/key.txt" "$RECIPIENT" "$ITERATIONS" "$armor")
        t_sharp=$(bench_op "$AGE_SHARP" decrypt "$TMPDIR/plain" "$TMPDIR/enc_sharp" "$TMPDIR/key.txt" "$RECIPIENT" "$ITERATIONS" "$armor")
        printf "%-10s | %-6s | %11s ms | %11s ms | %11s ms\n" "$label" "dec" "$t_age" "$t_rage" "$t_sharp"

        rm -f "$TMPDIR/enc_age" "$TMPDIR/enc_rage" "$TMPDIR/enc_sharp" "$TMPDIR/plain"
    done
}

run_suite "Binary" "no"
run_suite "ASCII Armor (-a)" "yes"

echo ""
echo "All times are average wall-clock milliseconds (lower is better)."
echo "Includes process startup, key parsing, header processing, and I/O."
