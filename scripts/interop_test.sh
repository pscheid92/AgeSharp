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

# --- Setup SSH RSA key ---
ssh-keygen -t rsa -b 4096 -f "$TMPDIR/ssh_rsa_key" -N "" -q
SSH_RSA_PUBKEY=$(cat "$TMPDIR/ssh_rsa_key.pub")

# --- Check for expect (needed for passphrase tests with Go age) ---
HAS_EXPECT=false
if command -v expect &>/dev/null; then
    HAS_EXPECT=true
fi

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

# --- Test 14: Passphrase — AgeSharp encrypt → Go age decrypt ---
echo ""
echo "$SEP"
echo "TEST 14: Passphrase — AgeSharp encrypt → Go age decrypt"
if $HAS_EXPECT; then
    echo "Passphrase sharp to go!" > "$TMPDIR/plain14.txt"
    AGE_PASSPHRASE="test-passphrase-14" $SHARP -p -o "$TMPDIR/enc14.age" "$TMPDIR/plain14.txt"
    expect -c "
        spawn $AGE --decrypt -o $TMPDIR/dec14.txt $TMPDIR/enc14.age
        expect \"Enter passphrase:\"
        send \"test-passphrase-14\r\"
        expect eof
        lassign [wait] pid spawnid os_error value
        exit \$value
    "
    RESULT=$(cat "$TMPDIR/dec14.txt")
    check "passphrase AgeSharp→Go" "Passphrase sharp to go!" "$RESULT"
else
    echo "  [SKIP] expect not available"
fi

# --- Test 15: Passphrase — Go age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 15: Passphrase — Go age encrypt → AgeSharp decrypt"
if $HAS_EXPECT; then
    echo "Passphrase go to sharp!" > "$TMPDIR/plain15.txt"
    expect -c "
        spawn $AGE --encrypt --passphrase -o $TMPDIR/enc15.age $TMPDIR/plain15.txt
        expect \"Enter passphrase\"
        send \"test-passphrase-15\r\"
        expect \"Confirm passphrase\"
        send \"test-passphrase-15\r\"
        expect eof
        lassign [wait] pid spawnid os_error value
        exit \$value
    "
    RESULT=$(AGE_PASSPHRASE="test-passphrase-15" $SHARP -d -p "$TMPDIR/enc15.age")
    check "passphrase Go→AgeSharp" "Passphrase go to sharp!" "$RESULT"
else
    echo "  [SKIP] expect not available"
fi

# --- Test 16: SSH RSA — Go age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 16: SSH RSA — Go age encrypt → AgeSharp decrypt"
echo "SSH RSA go to sharp!" | $AGE --encrypt -r "$SSH_RSA_PUBKEY" -o "$TMPDIR/enc16.age"
RESULT=$($SHARP -d -i "$TMPDIR/ssh_rsa_key" "$TMPDIR/enc16.age")
check "SSH RSA Go→AgeSharp" "SSH RSA go to sharp!" "$RESULT"

# --- Test 17: SSH RSA — AgeSharp encrypt → Go age decrypt ---
echo ""
echo "$SEP"
echo "TEST 17: SSH RSA — AgeSharp encrypt → Go age decrypt"
echo "SSH RSA sharp to go!" | $SHARP -r "$SSH_RSA_PUBKEY" -o "$TMPDIR/enc17.age"
RESULT=$($AGE --decrypt -i "$TMPDIR/ssh_rsa_key" "$TMPDIR/enc17.age")
check "SSH RSA AgeSharp→Go" "SSH RSA sharp to go!" "$RESULT"

# --- Test 18: Stdin/stdout pipe — AgeSharp encrypt → Go age decrypt ---
echo ""
echo "$SEP"
echo "TEST 18: Stdin/stdout pipe — AgeSharp encrypt → Go age decrypt"
RESULT=$(echo "Piped sharp to go!" | $SHARP -a -r "$GO_PUBKEY" | $AGE --decrypt -i "$TMPDIR/key_go.txt")
check "stdin/stdout AgeSharp→Go" "Piped sharp to go!" "$RESULT"

# --- Test 19: Stdin/stdout pipe — Go age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 19: Stdin/stdout pipe — Go age encrypt → AgeSharp decrypt"
RESULT=$(echo "Piped go to sharp!" | $AGE --encrypt --armor -r "$SHARP_PUBKEY" | $SHARP -d -i "$TMPDIR/key_sharp.txt")
check "stdin/stdout Go→AgeSharp" "Piped go to sharp!" "$RESULT"

# --- Test 20: Recipients file (-R) — encrypt, both decrypt ---
echo ""
echo "$SEP"
echo "TEST 20: Recipients file (-R) — encrypt, both decrypt"
cat > "$TMPDIR/recipients.txt" <<REOF
# This is a comment
$GO_PUBKEY

# Another comment
$SHARP_PUBKEY
REOF
echo "Recipients file!" | $SHARP -R "$TMPDIR/recipients.txt" -o "$TMPDIR/enc20.age"
RESULT1=$($AGE --decrypt -i "$TMPDIR/key_go.txt" "$TMPDIR/enc20.age")
RESULT2=$($SHARP -d -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc20.age")
check "recipients file — Go decrypts" "Recipients file!" "$RESULT1"
check "recipients file — AgeSharp decrypts" "Recipients file!" "$RESULT2"

# --- Test 21: Large file 10 MiB — AgeSharp encrypt → Go age decrypt ---
echo ""
echo "$SEP"
echo "TEST 21: Large file (10 MiB) — AgeSharp encrypt → Go age decrypt"
dd if=/dev/urandom bs=1048576 count=10 2>/dev/null > "$TMPDIR/large10.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc21.age" "$TMPDIR/large10.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec21.bin" "$TMPDIR/enc21.age"
diff "$TMPDIR/large10.bin" "$TMPDIR/dec21.bin" && ok "10 MiB AgeSharp→Go matches" || fail "10 MiB file mismatch"

# --- Test 22: Large file 10 MiB — Go age encrypt → AgeSharp decrypt ---
echo ""
echo "$SEP"
echo "TEST 22: Large file (10 MiB) — Go age encrypt → AgeSharp decrypt"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc22.age" "$TMPDIR/large10.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec22.bin" "$TMPDIR/enc22.age"
diff "$TMPDIR/large10.bin" "$TMPDIR/dec22.bin" && ok "10 MiB Go→AgeSharp matches" || fail "10 MiB file mismatch"

# --- Test 23: Multiple identity files (-i k1 -i k2) ---
echo ""
echo "$SEP"
echo "TEST 23: Multiple identity files — wrong key first, right key second"
$AGEKEYGEN -o "$TMPDIR/key_wrong.txt" 2>/dev/null
echo "Multi-identity!" | $AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc23.age"
RESULT=$($SHARP -d -i "$TMPDIR/key_wrong.txt" -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc23.age")
check "multi-identity decrypts with second key" "Multi-identity!" "$RESULT"

# --- Test 24: ASCII armor + passphrase — both directions ---
echo ""
echo "$SEP"
echo "TEST 24: ASCII armor + passphrase — both directions"
if $HAS_EXPECT; then
    echo "Armored passphrase!" > "$TMPDIR/plain24a.txt"
    AGE_PASSPHRASE="armor-pass-24" $SHARP -a -p -o "$TMPDIR/enc24a.age" "$TMPDIR/plain24a.txt"
    head -1 "$TMPDIR/enc24a.age" | grep -q "BEGIN AGE" && ok "armor+passphrase is armored" || fail "not armored"
    expect -c "
        spawn $AGE --decrypt -o $TMPDIR/dec24a.txt $TMPDIR/enc24a.age
        expect \"Enter passphrase:\"
        send \"armor-pass-24\r\"
        expect eof
        lassign [wait] pid spawnid os_error value
        exit \$value
    "
    RESULT=$(cat "$TMPDIR/dec24a.txt")
    check "armor+passphrase AgeSharp→Go" "Armored passphrase!" "$RESULT"

    echo "Go armored passphrase!" > "$TMPDIR/plain24b.txt"
    expect -c "
        spawn $AGE --encrypt --armor --passphrase -o $TMPDIR/enc24b.age $TMPDIR/plain24b.txt
        expect \"Enter passphrase\"
        send \"armor-pass-24b\r\"
        expect \"Confirm passphrase\"
        send \"armor-pass-24b\r\"
        expect eof
        lassign [wait] pid spawnid os_error value
        exit \$value
    "
    RESULT=$(AGE_PASSPHRASE="armor-pass-24b" $SHARP -d -p "$TMPDIR/enc24b.age")
    check "armor+passphrase Go→AgeSharp" "Go armored passphrase!" "$RESULT"
else
    echo "  [SKIP] expect not available"
fi

# --- Test 25: Empty file — encrypt and decrypt ---
echo ""
echo "$SEP"
echo "TEST 25: Empty file — encrypt and decrypt"
: > "$TMPDIR/empty.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc25.age" "$TMPDIR/empty.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec25.bin" "$TMPDIR/enc25.age"
BYTES=$(wc -c < "$TMPDIR/dec25.bin" | tr -d ' ')
check "empty file — AgeSharp encrypt, Go decrypt, 0 bytes" "0" "$BYTES"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc25b.age" "$TMPDIR/empty.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec25b.bin" "$TMPDIR/enc25b.age"
BYTES=$(wc -c < "$TMPDIR/dec25b.bin" | tr -d ' ')
check "empty file — Go encrypt, AgeSharp decrypt, 0 bytes" "0" "$BYTES"

# --- Test 26: Mixed recipient types — X25519 + SSH ed25519 + SSH RSA ---
echo ""
echo "$SEP"
echo "TEST 26: Mixed recipient types — X25519 + SSH ed25519 + SSH RSA"
echo "Mixed recipients!" | $SHARP -r "$GO_PUBKEY" -r "$SSH_PUBKEY" -r "$SSH_RSA_PUBKEY" -o "$TMPDIR/enc26.age"
RESULT1=$($AGE --decrypt -i "$TMPDIR/key_go.txt" "$TMPDIR/enc26.age")
RESULT2=$($SHARP -d -i "$TMPDIR/ssh_key" "$TMPDIR/enc26.age")
RESULT3=$($AGE --decrypt -i "$TMPDIR/ssh_rsa_key" "$TMPDIR/enc26.age")
check "mixed — X25519 decrypts" "Mixed recipients!" "$RESULT1"
check "mixed — SSH ed25519 decrypts" "Mixed recipients!" "$RESULT2"
check "mixed — SSH RSA decrypts" "Mixed recipients!" "$RESULT3"

# --- Test 27: keygen -y — cross-tool pubkey extraction ---
echo ""
echo "$SEP"
echo "TEST 27: keygen -y — cross-tool pubkey extraction"
GO_EXTRACTED=$($AGEKEYGEN -y "$TMPDIR/key_go.txt" 2>/dev/null)
SHARP_EXTRACTED=$($SHARP keygen -y "$TMPDIR/key_go.txt" 2>/dev/null)
check "keygen -y same pubkey from Go key" "$GO_EXTRACTED" "$SHARP_EXTRACTED"
GO_EXTRACTED2=$($AGEKEYGEN -y "$TMPDIR/key_sharp.txt" 2>/dev/null)
SHARP_EXTRACTED2=$($SHARP keygen -y "$TMPDIR/key_sharp.txt" 2>/dev/null)
check "keygen -y same pubkey from AgeSharp key" "$GO_EXTRACTED2" "$SHARP_EXTRACTED2"

# --- Test 28: Binary-safe — all 256 byte values ---
echo ""
echo "$SEP"
echo "TEST 28: Binary-safe — all 256 byte values"
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)))" > "$TMPDIR/allbytes.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc28.age" "$TMPDIR/allbytes.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec28.bin" "$TMPDIR/enc28.age"
diff "$TMPDIR/allbytes.bin" "$TMPDIR/dec28.bin" && ok "256 byte values roundtrip AgeSharp→Go" || fail "binary mismatch"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc28b.age" "$TMPDIR/allbytes.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec28b.bin" "$TMPDIR/enc28b.age"
diff "$TMPDIR/allbytes.bin" "$TMPDIR/dec28b.bin" && ok "256 byte values roundtrip Go→AgeSharp" || fail "binary mismatch"

# --- Test 29: 1 byte file ---
echo ""
echo "$SEP"
echo "TEST 29: 1 byte file — encrypt and decrypt"
printf '\x42' > "$TMPDIR/onebyte.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc29.age" "$TMPDIR/onebyte.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec29.bin" "$TMPDIR/enc29.age"
diff "$TMPDIR/onebyte.bin" "$TMPDIR/dec29.bin" && ok "1 byte AgeSharp→Go" || fail "1 byte mismatch"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc29b.age" "$TMPDIR/onebyte.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec29b.bin" "$TMPDIR/enc29b.age"
diff "$TMPDIR/onebyte.bin" "$TMPDIR/dec29b.bin" && ok "1 byte Go→AgeSharp" || fail "1 byte mismatch"

# --- Test 30: Exactly 64 KiB (one full STREAM chunk) ---
echo ""
echo "$SEP"
echo "TEST 30: Exactly 64 KiB (chunk boundary) — both directions"
dd if=/dev/urandom bs=65536 count=1 2>/dev/null > "$TMPDIR/chunk64k.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc30.age" "$TMPDIR/chunk64k.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec30.bin" "$TMPDIR/enc30.age"
diff "$TMPDIR/chunk64k.bin" "$TMPDIR/dec30.bin" && ok "64 KiB AgeSharp→Go" || fail "64 KiB mismatch"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc30b.age" "$TMPDIR/chunk64k.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec30b.bin" "$TMPDIR/enc30b.age"
diff "$TMPDIR/chunk64k.bin" "$TMPDIR/dec30b.bin" && ok "64 KiB Go→AgeSharp" || fail "64 KiB mismatch"

# --- Test 31: 64 KiB + 1 (forces second chunk) ---
echo ""
echo "$SEP"
echo "TEST 31: 64 KiB + 1 (second chunk boundary) — both directions"
dd if=/dev/urandom bs=65537 count=1 2>/dev/null > "$TMPDIR/chunk64k1.bin"
$SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc31.age" "$TMPDIR/chunk64k1.bin"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec31.bin" "$TMPDIR/enc31.age"
diff "$TMPDIR/chunk64k1.bin" "$TMPDIR/dec31.bin" && ok "64 KiB+1 AgeSharp→Go" || fail "64 KiB+1 mismatch"
$AGE --encrypt -r "$SHARP_PUBKEY" -o "$TMPDIR/enc31b.age" "$TMPDIR/chunk64k1.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec31b.bin" "$TMPDIR/enc31b.age"
diff "$TMPDIR/chunk64k1.bin" "$TMPDIR/dec31b.bin" && ok "64 KiB+1 Go→AgeSharp" || fail "64 KiB+1 mismatch"

# --- Test 32: Encrypted identity file ---
echo ""
echo "$SEP"
echo "TEST 32: Encrypted identity file"
if $HAS_EXPECT; then
    $AGEKEYGEN -o "$TMPDIR/key_encid.txt" 2>/dev/null
    ENCID_PUBKEY=$(grep "public key:" "$TMPDIR/key_encid.txt" | awk '{print $NF}')
    # Encrypt the identity file with AgeSharp using a passphrase
    AGE_PASSPHRASE="encid-pass" $SHARP -p -a -o "$TMPDIR/key_encid_encrypted.age" "$TMPDIR/key_encid.txt"
    # Encrypt data to the key's public key
    echo "Encrypted identity test!" | $SHARP -r "$ENCID_PUBKEY" -o "$TMPDIR/enc32.age"
    # Decrypt with AgeSharp using the encrypted identity
    RESULT=$(AGE_PASSPHRASE="encid-pass" $SHARP -d -i "$TMPDIR/key_encid_encrypted.age" "$TMPDIR/enc32.age")
    check "encrypted identity — AgeSharp decrypts" "Encrypted identity test!" "$RESULT"
    # Decrypt with Go age using the encrypted identity (prompts for passphrase)
    expect -c "
        spawn $AGE --decrypt -o $TMPDIR/dec32.txt -i $TMPDIR/key_encid_encrypted.age $TMPDIR/enc32.age
        expect \"Enter passphrase\"
        send \"encid-pass\r\"
        expect eof
        lassign [wait] pid spawnid os_error value
        exit \$value
    "
    RESULT=$(cat "$TMPDIR/dec32.txt")
    check "encrypted identity — Go decrypts" "Encrypted identity test!" "$RESULT"
else
    echo "  [SKIP] expect not available"
fi

# --- Test 33: Identity-based encryption (-i for encrypt) ---
echo ""
echo "$SEP"
echo "TEST 33: Identity-based encryption (-i for encrypt)"
echo "Identity encrypt!" | $SHARP -i "$TMPDIR/key_go.txt" -o "$TMPDIR/enc33.age"
RESULT=$($AGE --decrypt -i "$TMPDIR/key_go.txt" "$TMPDIR/enc33.age")
check "AgeSharp -i encrypt → Go decrypt" "Identity encrypt!" "$RESULT"
echo "Identity encrypt Go!" | $AGE --encrypt -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/enc33b.age"
RESULT=$($SHARP -d -i "$TMPDIR/key_sharp.txt" "$TMPDIR/enc33b.age")
check "Go -i encrypt → AgeSharp decrypt" "Identity encrypt Go!" "$RESULT"

# --- Test 34: Armored large file (1 MiB) ---
echo ""
echo "$SEP"
echo "TEST 34: Armored large file (1 MiB)"
dd if=/dev/urandom bs=1048576 count=1 2>/dev/null > "$TMPDIR/armor1m.bin"
$SHARP -a -r "$GO_PUBKEY" -o "$TMPDIR/enc34.age" "$TMPDIR/armor1m.bin"
head -1 "$TMPDIR/enc34.age" | grep -q "BEGIN AGE" && ok "1 MiB armored output is armored" || fail "not armored"
$AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec34.bin" "$TMPDIR/enc34.age"
diff "$TMPDIR/armor1m.bin" "$TMPDIR/dec34.bin" && ok "1 MiB armored AgeSharp→Go" || fail "1 MiB armored mismatch"
$AGE --encrypt --armor -r "$SHARP_PUBKEY" -o "$TMPDIR/enc34b.age" "$TMPDIR/armor1m.bin"
$SHARP -d -i "$TMPDIR/key_sharp.txt" -o "$TMPDIR/dec34b.bin" "$TMPDIR/enc34b.age"
diff "$TMPDIR/armor1m.bin" "$TMPDIR/dec34b.bin" && ok "1 MiB armored Go→AgeSharp" || fail "1 MiB armored mismatch"

# --- Test 35: Wrong passphrase fails gracefully ---
echo ""
echo "$SEP"
echo "TEST 35: Wrong passphrase fails gracefully"
echo "secret data" > "$TMPDIR/plain35.txt"
AGE_PASSPHRASE="correct-pass" $SHARP -p -o "$TMPDIR/enc35.age" "$TMPDIR/plain35.txt"
if AGE_PASSPHRASE="wrong-pass" $SHARP -d -p -o "$TMPDIR/dec35.txt" "$TMPDIR/enc35.age" 2>/dev/null; then
    fail "wrong passphrase should have failed"
else
    ok "wrong passphrase rejected by AgeSharp"
fi

# --- Test 36: Wrong key fails gracefully ---
echo ""
echo "$SEP"
echo "TEST 36: Wrong key fails gracefully"
echo "secret data" | $SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc36.age"
if $SHARP -d -i "$TMPDIR/key_wrong.txt" -o "$TMPDIR/dec36.txt" "$TMPDIR/enc36.age" 2>/dev/null; then
    fail "wrong key should have failed (AgeSharp)"
else
    ok "wrong key rejected by AgeSharp"
fi
if $AGE --decrypt -i "$TMPDIR/key_wrong.txt" -o "$TMPDIR/dec36b.txt" "$TMPDIR/enc36.age" 2>/dev/null; then
    fail "wrong key should have failed (Go)"
else
    ok "wrong key rejected by Go age"
fi

# --- Test 37: Tampered ciphertext rejected ---
echo ""
echo "$SEP"
echo "TEST 37: Tampered ciphertext rejected"
echo "tamper test" | $SHARP -r "$GO_PUBKEY" -o "$TMPDIR/enc37.age"
cp "$TMPDIR/enc37.age" "$TMPDIR/enc37_tampered.age"
# Flip the last byte of the file (in the payload area)
python3 -c "
import sys
with open(sys.argv[1], 'r+b') as f:
    f.seek(-1, 2)
    b = f.read(1)
    f.seek(-1, 2)
    f.write(bytes([b[0] ^ 0xFF]))
" "$TMPDIR/enc37_tampered.age"
if $SHARP -d -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec37.txt" "$TMPDIR/enc37_tampered.age" 2>/dev/null; then
    fail "tampered ciphertext should have failed (AgeSharp)"
else
    ok "tampered ciphertext rejected by AgeSharp"
fi
if $AGE --decrypt -i "$TMPDIR/key_go.txt" -o "$TMPDIR/dec37b.txt" "$TMPDIR/enc37_tampered.age" 2>/dev/null; then
    fail "tampered ciphertext should have failed (Go)"
else
    ok "tampered ciphertext rejected by Go age"
fi

# --- Test 38: Inspect armored file ---
echo ""
echo "$SEP"
echo "TEST 38: Inspect armored file"
echo "inspect armored" | $SHARP -a -r "$GO_PUBKEY" -o "$TMPDIR/enc38.age"
INSPECT=$($SHARP inspect "$TMPDIR/enc38.age" 2>&1)
echo "$INSPECT" | grep -q "X25519" && ok "inspect armored shows X25519" || fail "inspect armored missing X25519"

# --- Test 39: Inspect passphrase-encrypted file ---
echo ""
echo "$SEP"
echo "TEST 39: Inspect passphrase-encrypted file"
echo "inspect scrypt" > "$TMPDIR/plain39.txt"
AGE_PASSPHRASE="inspect-pass" $SHARP -p -o "$TMPDIR/enc39.age" "$TMPDIR/plain39.txt"
INSPECT=$($SHARP inspect "$TMPDIR/enc39.age" 2>&1)
echo "$INSPECT" | grep -q "scrypt" && ok "inspect passphrase shows scrypt" || fail "inspect passphrase missing scrypt"

# --- Summary ---
echo ""
echo "$SEP"
echo "RESULTS: $PASS passed, $FAIL failed"
echo "$SEP"
[ $FAIL -eq 0 ] && exit 0 || exit 1
