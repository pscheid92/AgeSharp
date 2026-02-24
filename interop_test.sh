#!/bin/bash
# Interoperability test: AgeSharp CLI vs Go age CLI
#
# Requires:
#   - age and age-keygen on PATH (https://github.com/FiloSottile/age)
#   - dotnet on PATH (.NET 10+)
#
# Usage:
#   ./interop_test.sh [path/to/Age.Cli.dll]
#
# If no DLL path is given, the script builds Age.Cli from source first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEP="---------------------------------------------"
PASS=0
FAIL=0

ok()    { echo "  [OK]   $1"; PASS=$((PASS+1)); }
fail()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then ok "$label"; else fail "$label (expected: '$expected', got: '$actual')"; fi
}

# --- Locate tools ---
if ! command -v age &>/dev/null; then
    echo "Error: 'age' not found on PATH. Install from https://github.com/FiloSottile/age"
    exit 1
fi
if ! command -v age-keygen &>/dev/null; then
    echo "Error: 'age-keygen' not found on PATH."
    exit 1
fi
if ! command -v dotnet &>/dev/null; then
    echo "Error: 'dotnet' not found on PATH."
    exit 1
fi

AGE="age"
AGEKEYGEN="age-keygen"

# --- Build or locate AgeSharp CLI ---
if [ -n "${1:-}" ]; then
    # Accept either a native binary or a .dll
    if [[ "$1" == *.dll ]]; then
        SHARP="dotnet $1"
    else
        SHARP="$1"
    fi
else
    echo "Building Age.Cli..."
    BUILD_OUT="$(mktemp -d)"
    dotnet build "$SCRIPT_DIR/Age.Cli" -o "$BUILD_OUT" -v quiet 2>&1
    SHARP="dotnet $BUILD_OUT/Age.Cli.dll"
fi

# --- Temp dir for test artifacts ---
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "$SEP"
echo "age version:     $($AGE --version)"
echo "AgeSharp version: $($SHARP --version)"
echo "$SEP"

# --- Setup keys ---
$AGEKEYGEN -o "$TMPDIR/key_go.txt" 2>/dev/null
GO_PUBKEY=$(grep "public key:" "$TMPDIR/key_go.txt" | awk '{print $NF}')

$SHARP keygen -o "$TMPDIR/key_sharp.txt" 2>/dev/null
SHARP_PUBKEY=$(grep "public key:" "$TMPDIR/key_sharp.txt" | awk '{print $NF}')

echo "Keys"
echo "  Go:       $GO_PUBKEY"
echo "  AgeSharp: $SHARP_PUBKEY"

# --- Test 1: age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 1: age encrypt → AgeSharp decrypt"
echo "Hello from Go age!" | $AGE --encrypt -r "$GO_PUBKEY" -o "$TMPDIR/enc1.age"
RESULT=$($SHARP -d -i "$TMPDIR/key_go.txt" "$TMPDIR/enc1.age")
check "decrypted correctly" "Hello from Go age!" "$RESULT"

# --- Test 2: AgeSharp encrypt → age decrypt ---
echo ""
echo "$SEP"
echo "TEST 2: AgeSharp encrypt → age decrypt"
echo "Hello from AgeSharp!" | $SHARP -r "$SHARP_PUBKEY" -o "$TMPDIR/enc2.age"
RESULT=$($AGE --decrypt -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc2.age")
check "decrypted correctly" "Hello from AgeSharp!" "$RESULT"

# --- Test 3: age key → AgeSharp encrypt → age decrypt ---
echo ""
echo "$SEP"
echo "TEST 3: age key → AgeSharp encrypt → age decrypt"
echo "Cross-tool roundtrip!" | $SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc3.age"
RESULT=$($AGE --decrypt -i "$TMPDIR/key_go.txt" "$TMPDIR/enc3.age")
check "decrypted correctly" "Cross-tool roundtrip!" "$RESULT"

# --- Test 4: AgeSharp key → age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 4: AgeSharp key → age encrypt → AgeSharp decrypt"
echo "Other direction!" | $AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc4.age"
RESULT=$($SHARP -d -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc4.age")
check "decrypted correctly" "Other direction!" "$RESULT"

# --- Test 5: ASCII armor — AgeSharp encrypt → age decrypt ---
echo ""
echo "$SEP"
echo "TEST 5: ASCII armor — AgeSharp encrypt → age decrypt"
echo "Armored!" | $SHARP -a -r "$GO_PUBKEY" -o "$TMPDIR/enc5.age"
head -1 "$TMPDIR/enc5.age" | grep -q "BEGIN AGE" && ok "output is armored" || fail "output is not armored"
RESULT=$($AGE --decrypt -i "$TMPDIR/key_go.txt" "$TMPDIR/enc5.age")
check "decrypted correctly" "Armored!" "$RESULT"

# --- Test 6: ASCII armor — age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 6: ASCII armor — age encrypt → AgeSharp decrypt"
echo "Go armored!" | $AGE --encrypt --armor -r "$SHARP_PUBKEY" -o "$TMPDIR/enc6.age"
head -1 "$TMPDIR/enc6.age" | grep -q "BEGIN AGE" && ok "output is armored" || fail "output is not armored"
RESULT=$($SHARP -d -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc6.age")
check "decrypted correctly" "Go armored!" "$RESULT"

# --- Test 7: Multi-recipient — AgeSharp encrypt, both tools can decrypt ---
echo ""
echo "$SEP"
echo "TEST 7: Multi-recipient — AgeSharp encrypt, age and AgeSharp both decrypt"
echo "Multi-recipient!" | $SHARP -r "$GO_PUBKEY" -r "$SHARP_PUBKEY" -o "$TMPDIR/enc7.age"
RESULT1=$($AGE --decrypt -i "$TMPDIR/key_go.txt" "$TMPDIR/enc7.age")
RESULT2=$($SHARP -d -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc7.age")
check "age decrypts with Go key" "Multi-recipient!" "$RESULT1"
check "AgeSharp decrypts with Sharp key" "Multi-recipient!" "$RESULT2"

# --- Test 8: SSH ed25519 — age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 8: SSH ed25519 — age encrypt → AgeSharp decrypt"
ssh-keygen -t ed25519 -f "$TMPDIR/ssh_key" -N "" -q
SSH_PUBKEY=$(cat "$TMPDIR/ssh_key.pub")
echo "SSH roundtrip!" | $AGE --encrypt -r "$SSH_PUBKEY" -o "$TMPDIR/enc8.age"
RESULT=$($SHARP -d -i "$TMPDIR/ssh_key" "$TMPDIR/enc8.age")
check "SSH ed25519 decrypted correctly" "SSH roundtrip!" "$RESULT"

# --- Test 9: SSH ed25519 — AgeSharp encrypt → age decrypt ---
echo ""
echo "$SEP"
echo "TEST 9: SSH ed25519 — AgeSharp encrypt → age decrypt"
echo "SSH AgeSharp!" | $SHARP -r "$SSH_PUBKEY" -o "$TMPDIR/enc9.age"
RESULT=$($AGE --decrypt -i "$TMPDIR/ssh_key" "$TMPDIR/enc9.age")
check "SSH ed25519 decrypted correctly" "SSH AgeSharp!" "$RESULT"

# --- Test 10: age inspect on age-generated file ---
echo ""
echo "$SEP"
echo "TEST 10: age inspect on age-generated file"
echo "inspect me" | $AGE --encrypt -r "$GO_PUBKEY" -o "$TMPDIR/enc10.age"
$SHARP inspect "$TMPDIR/enc10.age"
ok "inspect completed without error"

# --- Test 11: age inspect on AgeSharp multi-recipient file ---
echo ""
echo "$SEP"
echo "TEST 11: age inspect on AgeSharp multi-recipient file"
echo "inspect me" | $SHARP -r "$GO_PUBKEY" -r "$SHARP_PUBKEY" -o "$TMPDIR/enc11.age"
$SHARP inspect "$TMPDIR/enc11.age"
ok "inspect completed without error"

# --- Test 12: Large file — AgeSharp encrypt → age decrypt ---
echo ""
echo "$SEP"
echo "TEST 12: Large file (200 KiB) — AgeSharp encrypt → age decrypt"
dd if=/dev/urandom bs=1024 count=200 2>/dev/null > "$TMPDIR/large.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc12.age" "$TMPDIR/large.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec12.bin" "$TMPDIR/enc12.age"
diff "$TMPDIR/large.bin" "$TMPDIR/dec12.bin" && ok "200 KiB file matches byte-for-byte" || fail "file mismatch"

# --- Test 13: Large file — age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 13: Large file (200 KiB) — age encrypt → AgeSharp decrypt"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc13.age" "$TMPDIR/large.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec13.bin" "$TMPDIR/enc13.age"
diff "$TMPDIR/large.bin" "$TMPDIR/dec13.bin" && ok "200 KiB file matches byte-for-byte" || fail "file mismatch"

# --- Summary ---
echo ""
echo "$SEP"
echo "RESULTS: $PASS passed, $FAIL failed"
echo "$SEP"
[ $FAIL -eq 0 ] && exit 0 || exit 1
