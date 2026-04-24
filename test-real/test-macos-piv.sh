#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

. "$(cd "$(dirname "$0")" && pwd)/macos-common.sh"

YUBICO_PIV_TOOL="${YUBICO_PIV_TOOL:-$(find_cmd yubico-piv-tool)}"
OPENSSL_BIN="${OPENSSL_BIN:-$(find_cmd openssl)}"
OPENSC_TOOL="${OPENSC_TOOL:-$(find_cmd opensc-tool)}"
PKCS15_TOOL="${PKCS15_TOOL:-$(find_cmd pkcs15-tool)}"
PKCS11_TOOL="${PKCS11_TOOL:-$(find_cmd pkcs11-tool)}"

[[ -n "$YUBICO_PIV_TOOL" ]] || die "missing required command: yubico-piv-tool"
[[ -n "$OPENSSL_BIN" ]] || die "missing required command: openssl"
[[ -n "$OPENSC_TOOL" ]] || die "missing required command: opensc-tool"
[[ -n "$PKCS15_TOOL" ]] || die "missing required command: pkcs15-tool"
[[ -n "$PKCS11_TOOL" ]] || die "missing required command: pkcs11-tool"

export TEST_TMP_DIR="${TEST_TMP_DIR:-/tmp/canokey-macos-piv}"

OPENSC_PKCS11_MODULE_RESOLVED="$(macos_find_opensc_pkcs11_module)"
PKCS11_ARGS=()
if [[ -n "$OPENSC_PKCS11_MODULE_RESOLVED" ]]; then
    PKCS11_ARGS=(--module "$OPENSC_PKCS11_MODULE_RESOLVED")
fi

YPT() {
    "$YUBICO_PIV_TOOL" -r "$RDID" "$@"
}

OSC() {
    "$OPENSC_TOOL" --reader "$RDID" "$@"
}

PKCS15() {
    "$PKCS15_TOOL" --reader "$RDID" "$@"
}

PKCS11Slot() {
    "$PKCS11_TOOL" "${PKCS11_ARGS[@]}" -L | awk '
        /^Slot / {
            slot = $2
            gsub(/[():]/, "", slot)
            print slot
            exit
        }'
}

PKCS11() {
    "$PKCS11_TOOL" "${PKCS11_ARGS[@]}" "$@"
}

OpenSSLSupportsGenpkey() {
    local algo="$1"
    local out="$TEST_TMP_DIR/openssl-probe-$algo.pem"
    "$OPENSSL_BIN" genpkey -algorithm "$algo" -out "$out" >/dev/null 2>&1
}

PIVGenKeyCert() {
    local key="$1"
    local subject="$2"
    local algo="$3"
    echo "========================== PIV generate/selfsign slot=$key algo=$algo =========================="
    YPT -a delete-certificate -s "$key" >/dev/null 2>&1 || true
    YPT -a generate -A "$algo" -s "$key" >"$TEST_TMP_DIR/pubkey-$key.pem"
    assertEquals 'yubico-piv-tool generate' 0 $?
    if [[ "$algo" == "X25519" ]]; then
        return
    fi
    YPT -P 654321 -A "$algo" -a verify-pin -a selfsign-certificate -s "$key" -S "$subject" <"$TEST_TMP_DIR/pubkey-$key.pem" >"$TEST_TMP_DIR/cert-$key.pem"
    assertEquals 'yubico-piv-tool selfsign-certificate' 0 $?
    YPT -a import-certificate -s "$key" <"$TEST_TMP_DIR/cert-$key.pem"
    assertEquals 'yubico-piv-tool import-certificate' 0 $?
}

PIVImportKeyCert() {
    local key="$1"
    local priv_pem="$2"
    local cert_pem="$3"
    echo "========================== PIV import slot=$key key=$priv_pem cert=$cert_pem =========================="
    YPT -a import-key -s "$key" -i "$priv_pem"
    assertEquals 'import-key' 0 $?
    if [[ -f "$cert_pem" ]]; then
        YPT -a import-certificate -s "$key" -i "$cert_pem"
        assertEquals 'import-certificate' 0 $?
        cp "$cert_pem" "$TEST_TMP_DIR/cert-$key.pem"
    fi
}

PIVSignDec() {
    local key="$1"
    local pinArgs=()
    local op="$3"
    local algoArgs=()
    local inp_file="$TEST_TMP_DIR/cert-$key.pem"
    echo "========================== PIV sign/decipher slot=$key op=${op:-both} algo=${4:-default} =========================="
    if [[ "$4" == X25519 ]]; then
        inp_file="$TEST_TMP_DIR/pubkey-$key.pem"
    fi
    if [[ -n "$2" ]]; then
        pinArgs=(-P 654321 -a verify-pin)
    fi
    if [[ -n "$4" ]]; then
        algoArgs=(-A "$4")
    fi
    if [[ -z "$op" || "$op" == s ]]; then
        YPT "${pinArgs[@]}" -a test-signature -s "$key" <"$inp_file"
        assertEquals 'yubico-piv-tool test-signature' 0 $?
    fi
    if [[ -z "$op" || "$op" == d ]]; then
        YPT "${pinArgs[@]}" -a test-decipher -s "$key" "${algoArgs[@]}" <"$inp_file"
        assertEquals 'yubico-piv-tool test-decipher' 0 $?
    fi
}

oneTimeSetUp() {
    rm -rf "$TEST_TMP_DIR"
    mkdir -p "$TEST_TMP_DIR"
    chmod 700 "$TEST_TMP_DIR"

    export RDID="${RDID:-$(macos_find_piv_reader)}"
    [[ -n "$RDID" ]] || die "no PIV reader found"
    echo "RDID=$RDID"
    if [[ -n "$OPENSC_PKCS11_MODULE_RESOLVED" ]]; then
        echo "OpenSC PKCS#11 module: $OPENSC_PKCS11_MODULE_RESOLVED"
    fi
}

test_PivInfo() {
    local out
    echo "Reader: {$RDID}"
    YPT -v -a set-ccc -a set-chuid -a status
    assertEquals 'yubico-piv-tool status' 0 $?

    out=$(OSC -s '00 F8 00 00')
    assertContains 'PIV_INS_GET_SERIAL' "$out" 'SW1=0x90, SW2=0x00'

    out=$(OSC -s '00 FD 00 00')
    assertContains 'PIV_INS_GET_VERSION' "$out" 'SW1=0x90, SW2=0x00'

    PKCS15 -D
    assertEquals 'pkcs15-tool dump' 0 $?
}

test_ChangePin() {
    local out
    YPT -a verify-pin -P 123456
    YPT -a change-pin -P 123456 -N 654321
    YPT -a verify-pin -P 654321
    out=$(YPT -a verify-pin -P 123456 2>&1)
    assertContains 'verify-pin' "$out" '2 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 123456 2>&1)
    assertContains 'verify-pin' "$out" '1 tries left before pin is blocked.'
    YPT -a verify-pin -P 654321
    assertEquals 'verify-pin' 0 $?
    YPT -a set-mgm-key -n F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8
    assertEquals 'set-mgm-key' 0 $?
    YPT -a set-mgm-key --key=F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8F1F2F3F4F5F6F7F8 -n 010203040506070801020304050607080102030405060708
    assertEquals 'set-mgm-key' 0 $?
}

rsa_tests() {
    local algo="$1"
    local s out slot
    for s in 9a 9c 9d 9e; do
        PIVGenKeyCert "$s" "/CN=CertAtSlot$s/" "$algo"
    done
    YPT -a status
    PIVSignDec 9e
    for s in 9a 9c 9d; do
        PIVSignDec "$s" 1
    done

    out=$(PKCS15 --read-certificate 04 | "$OPENSSL_BIN" x509 -text)
    assertContains 'CERT' "$out" 'CN = CertAtSlot9e'
    echo -n hello >"$TEST_TMP_DIR/hello.txt"
    slot="${PKCS11_SLOT:-$(PKCS11Slot)}"
    [[ -n "$slot" ]] || die "no PKCS#11 slot found"
    PKCS11 --slot "$slot" -d 04 -s -m SHA256-RSA-PKCS -i "$TEST_TMP_DIR/hello.txt" -o "$TEST_TMP_DIR/hello-signed" --pin 654321
    assertEquals 'pkcs11-tool sign' 0 $?
    "$OPENSSL_BIN" dgst -sha256 -verify "$TEST_TMP_DIR/pubkey-9e.pem" -signature "$TEST_TMP_DIR/hello-signed" "$TEST_TMP_DIR/hello.txt"
    assertEquals 'openssl dgst verify' 0 $?
}

test_RSA2048() {
    rsa_tests RSA2048
}

test_RSA3072() {
    rsa_tests RSA3072
}

test_RSA4096() {
    rsa_tests RSA4096
}

ec_tests() {
    local algo="$1"
    local s out
    for s in 9a 9c 9d 9e; do
        PIVGenKeyCert "$s" "/CN=CertAtSlot$s/" "$algo"
    done
    YPT -a status
    for s in 9a 9c 9d 9e; do
        if [[ "$algo" != "X25519" ]]; then
            PIVSignDec "$s" 1 s "$algo"
        fi
        if [[ "$algo" != "ED25519" ]]; then
            PIVSignDec "$s" 1 d "$algo"
        fi
    done
    if [[ "$algo" != *25519 ]]; then
        out=$(PKCS15 --read-certificate 01 | "$OPENSSL_BIN" x509 -text)
        assertContains 'CERT' "$out" 'CN = CertAtSlot9a'
        out=$(PKCS15 --read-certificate 02 | "$OPENSSL_BIN" x509 -text)
        assertContains 'CERT' "$out" 'CN = CertAtSlot9c'
    fi
}

test_ECC256() {
    ec_tests ECCP256
}

test_ECC384() {
    ec_tests ECCP384
}

test_25519() {
    ec_tests ED25519
    ec_tests X25519
}

test_PinBlock() {
    local out
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" '2 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" '1 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains 'verify-pin' "$out" 'Pin code blocked'
    out=$(YPT -a verify-pin -P 654321 2>&1)
    assertContains 'verify-pin' "$out" 'Pin code blocked'
    out=$(YPT -a unblock-pin -P 12345678 -N 999999 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully unblocked the pin code'
    out=$(YPT -a change-puk -P 12345678 -N 87654321 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully changed the puk code'
    out=$(YPT -a unblock-pin -P 87654321 -N 654321 2>&1)
    assertContains 'verify-pin' "$out" 'Successfully unblocked the pin code'
}

test_ECKeyImport() {
    local algo opt s
    local algos=("ECCP256" "ECCP384" "ED25519" "X25519")
    for algo in "${algos[@]}"; do
        case "$algo" in
            ECCP256) opt="-algorithm EC -pkeyopt ec_paramgen_curve:prime256v1" ;;
            ECCP384) opt="-algorithm EC -pkeyopt ec_paramgen_curve:secp384r1" ;;
            ED25519) opt="-algorithm ED25519" ;;
            X25519) opt="-algorithm X25519" ;;
        esac
        if [[ "$algo" == ED25519 || "$algo" == X25519 ]]; then
            if ! OpenSSLSupportsGenpkey "$algo"; then
                echo "OpenSSL does not support $algo genpkey; skipping import checks for this algorithm"
                continue
            fi
        fi
        for s in 9a 9c 9d 9e; do
            rm -f "$TEST_TMP_DIR/cert-$algo-$s.pem"
            # shellcheck disable=SC2086
            "$OPENSSL_BIN" genpkey $opt -out "$TEST_TMP_DIR/key-$s.pem"
            assertEquals 'openssl genpkey' 0 $?
            "$OPENSSL_BIN" req -x509 -key "$TEST_TMP_DIR/key-$s.pem" -out "$TEST_TMP_DIR/cert-$algo-$s.pem" -days 365 -nodes -subj "/CN=www.example.com" >/dev/null 2>&1 || true
            PIVImportKeyCert "$s" "$TEST_TMP_DIR/key-$s.pem" "$TEST_TMP_DIR/cert-$algo-$s.pem"
            "$OPENSSL_BIN" pkey -in "$TEST_TMP_DIR/key-$s.pem" -pubout -out "$TEST_TMP_DIR/pubkey-$s.pem"
        done
        YPT -a status
        for s in 9a 9c 9d 9e; do
            if [[ "$algo" != X25519 ]]; then
                PIVSignDec "$s" 1 s "$algo"
            fi
            if [[ "$algo" != ED25519 ]]; then
                PIVSignDec "$s" 1 d "$algo"
            fi
        done
    done
}

test_RSAKeyImport() {
    local s
    "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -keyout "$TEST_TMP_DIR/key.pem" -out "$TEST_TMP_DIR/cert.pem" -days 365 -nodes -subj "/CN=www.example.com"
    assertEquals 'openssl gen key' 0 $?

    for s in 9a 9c 9d 9e; do
        PIVImportKeyCert "$s" "$TEST_TMP_DIR/key.pem" "$TEST_TMP_DIR/cert.pem"
    done
    YPT -a status
    PIVSignDec 9e
    for s in 9a 9c 9d; do
        PIVSignDec "$s" 1
    done
}

test_FactoryReset() {
    local out
    out=$(YPT -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'Failed verifying puk code, now 2 tries left before blocked'
    out=$(YPT -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'Failed verifying puk code, now 1 tries left before blocked'
    out=$(YPT -a change-puk -P 12345678 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'The puk code is blocked'
    out=$(YPT -a change-puk -P 87654321 -N 11111111 2>&1)
    assertContains "change-puk" "$out" 'The puk code is blocked'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" '2 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" '1 tries left before pin is blocked.'
    out=$(YPT -a verify-pin -P 222222 2>&1)
    assertContains "verify-pin" "$out" 'Pin code blocked'
    YPT -a reset
    assertEquals 'reset' 0 $?
    out=$(YPT -a unblock-pin -P 12345678 -N 654321 2>&1)
    assertContains "unblock-pin" "$out" 'Successfully unblocked the pin code'
}

test_FillData() {
    local s
    "$OPENSSL_BIN" req -x509 -newkey rsa:4096 -keyout "$TEST_TMP_DIR/key.pem" -out "$TEST_TMP_DIR/cert.pem" -days 365 -nodes -subj "/CN=www.example.com"
    assertEquals 'openssl gen key' 0 $?
    "$OPENSSL_BIN" rand -base64 -out "$TEST_TMP_DIR/rand-pi" 242
    YPT -a write-object --id 0x5fc109 -i "$TEST_TMP_DIR/rand-pi" -f base64
    YPT -a write-object --id 0x5fc108 -i "$TEST_TMP_DIR/rand-pi" -f base64
    YPT -a write-object --id 0x5fc103 -i "$TEST_TMP_DIR/rand-pi" -f base64
    for s in 9a 9c 9d 9e 82 83; do
        PIVImportKeyCert "$s" "$TEST_TMP_DIR/key.pem" "$TEST_TMP_DIR/cert.pem"
        assertEquals 'import-key' 0 $?
    done
    YPT -a status
}

if [[ $# -gt 0 && "${1:-}" != "--" ]]; then
    set -- -- "$@"
fi

. "$TEST_REAL_DIR/shunit2/shunit2"
