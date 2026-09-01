#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

. "$(cd "$(dirname "$0")" && pwd)/macos-common.sh"

GPG_BIN="${GPG_BIN:-$(find_cmd gpg gpg2)}"
GPGCONF_BIN="${GPGCONF_BIN:-$(find_cmd gpgconf)}"

[[ -n "$GPG_BIN" ]] || die "missing required command: gpg"
[[ -n "$GPGCONF_BIN" ]] || die "missing required command: gpgconf"
require_file "$TEST_REAL_DIR/pinentry-mock"

export GNUPGHOME="${GNUPGHOME:-$TEST_REAL_DIR/temp_macos_gnupg}"

GPGCmd() {
    "$GPG_BIN" --homedir "$GNUPGHOME" --command-fd 0 --yes --expert "$@"
}

Addkey() {
    [[ -z "$1" || -z "$2" ]] && echo "Wrong arguments!" && exit 1
    printf "addkey\n%s\n%s\n0\nsave\n" "$1" "$2" | GPGCmd --edit-key "$KEYID"
    assertEquals 'Addkey failed' 0 $?
}

KeyUsageS2A() {
    printf "key %s\nchange-usage\nS\nA\nQ\nsave\n" "$1" | GPGCmd --edit-key "$KEYID"
    assertEquals 'KeyUsageS2A failed' 0 $?
}

Addcardkey() {
    printf "addcardkey\n%s\n0\nsave\n" "$1" | GPGCmd --edit-key "$KEYID"
    assertEquals 'Addcardkey failed' 0 $?
}

Delkey() {
    local keys="" nl=$'\n' k
    for k in "$@"; do
        keys="${keys}key ${k}${nl}"
    done
    printf "%sdelkey\ny\nsave\n" "$keys" | GPGCmd --edit-key "$KEYID"
}

Key2card() {
    printf "key %s\nkeytocard\n%s\nsave\n" "$1" "$2" | GPGCmd --edit-key "$KEYID"
    assertEquals 'Key2card failed' 0 $?
    "$GPG_BIN" --homedir "$GNUPGHOME" --card-status
}

GPGReset() {
    printf "admin\nfactory-reset\ny\nyes\n" | GPGCmd --edit-card
    assertEquals 'GPG reset failed' 0 $?
}

GPGSign() {
    local k
    k=$("$GPG_BIN" --homedir "$GNUPGHOME" -K --with-colons | awk -F: '$1 ~ /ssb/ && $12 ~ /s/ {print $5}' | tail -n 1)
    echo "========================== Test Signing with $k =========================="
    [[ -z "$k" ]] && echo "Key not found!" && exit 1
    macos_timestamp | "$GPG_BIN" --homedir "$GNUPGHOME" --armor --default-key "${k}!" -s | "$GPG_BIN" --homedir "$GNUPGHOME"
    assertEquals 'GPG sign failed' 0 $?
}

GPGEnc() {
    local k
    k=$("$GPG_BIN" --homedir "$GNUPGHOME" -K --with-colons | awk -F: '$1 ~ /ssb/ && $12 ~ /e/ {print $5}' | tail -n 1)
    echo "========================== Test Encryption with $k =========================="
    [[ -z "$k" ]] && echo "Key not found!" && exit 1
    macos_timestamp | "$GPG_BIN" --homedir "$GNUPGHOME" --yes --armor --recipient "$k" --encrypt | "$GPG_BIN" --homedir "$GNUPGHOME"
    assertEquals 'GPG encrypt failed' 0 $?
}

GenerateKeyOnCard() {
    printf "admin\nkey-attr\n%s\n%s\n%s\n%s\n%s\n%s\n" "$1" "$2" "$1" "$2" "$1" "$2" | GPGCmd --edit-card
    Addcardkey 1
    Addcardkey 2
    Addcardkey 3
}

oneTimeSetUp() {
    macos_mk_private_dir "$GNUPGHOME"

    cp "$TEST_REAL_DIR/pinentry-mock" "$GNUPGHOME/"
    chmod 755 "$GNUPGHOME/pinentry-mock"
    cat >"$GNUPGHOME/gpg-agent.conf" <<EOF
pinentry-program $GNUPGHOME/pinentry-mock
debug 1031
debug-level 8
log-file $GNUPGHOME/gpg-agent.log
EOF
    cat >"$GNUPGHOME/scdaemon.conf" <<EOF
disable-ccid
pcsc-driver /System/Library/Frameworks/PCSC.framework/PCSC
debug 6145
log-file $GNUPGHOME/scdaemon.log
EOF

    "$GPGCONF_BIN" --homedir "$GNUPGHOME" --kill gpg-agent >/dev/null 2>&1 || true
    "$GPGCONF_BIN" --homedir "$GNUPGHOME" --kill scdaemon >/dev/null 2>&1 || true

    "$GPG_BIN" --homedir "$GNUPGHOME" --version
    "$GPG_BIN" --homedir "$GNUPGHOME" --card-status || true
    "$GPG_BIN" --homedir "$GNUPGHOME" --card-status || exit 1
    printf "Key-Type: 1\nKey-Length: 2048\nSubkey-Type: 1\nSubkey-Length: 2048\nName-Real: Someone\nName-Email: foo@example.com\nPassphrase: 12345678\n%%commit\n%%echo done\n" |
        "$GPG_BIN" --homedir "$GNUPGHOME" --batch --gen-key -v
    export KEYID
    KEYID=$("$GPG_BIN" --homedir "$GNUPGHOME" -K --with-colons | grep -E '^sec' | grep -Eo '[[:alnum:]]{16}' | head -n 1)
    echo "Key Id is: $KEYID"
    GPGReset
    Delkey 1
}

oneTimeTearDown() {
    "$GPGCONF_BIN" --homedir "$GNUPGHOME" --kill gpg-agent >/dev/null 2>&1 || true
    "$GPGCONF_BIN" --homedir "$GNUPGHOME" --kill scdaemon >/dev/null 2>&1 || true
}

test_Sanity() {
    Addkey 10 3
    Key2card 1 1
    GPGSign
    Delkey 1
    Addkey 12 3
    Key2card 1 2
    GPGEnc
    Delkey 1
}

test_ImportedKeys() {
    local pair param_enc param_sig i
    local ALGO_PAIRS=(
        "4 2048,6 2048"
        "4 3072,6 3072"
        "4 4096,6 4096"
    )
    for ((i = 0; i < ${#ALGO_PAIRS[@]}; i++)); do
        pair="${ALGO_PAIRS[$i]}"
        echo "------------------- <$pair> -------------------"
        param_enc="${pair##*,}"
        param_sig="${pair%%,*}"
        echo "========================== Signature<$param_sig> =========================="
        Addkey $param_sig
        Key2card 1 1
        echo "========================== Encryption<$param_enc> =========================="
        Addkey $param_enc
        Key2card 2 2
        echo "========================== Authentication<$param_sig> =========================="
        Addkey $param_sig
        KeyUsageS2A 3
        Key2card 3 3
        GPGSign
        GPGEnc
        Delkey 1 2 3
        GPGReset
    done
}

test_GeneratedKeys() {
    local pair i
    local ALGO_PAIRS=(
        "1 2048"
        "1 3072"
        "1 4096"
        "2 3"
        "2 4"
        "2 1"
    )
    for ((i = 0; i < ${#ALGO_PAIRS[@]}; i++)); do
        pair="${ALGO_PAIRS[$i]}"
        echo "------------------- <$pair> -------------------"
        GenerateKeyOnCard $pair
        GPGSign
        GPGEnc
        Delkey 1 2 3
        GPGReset
    done
}

if [[ $# -gt 0 && "${1:-}" != "--" ]]; then
    set -- -- "$@"
fi

. "$TEST_REAL_DIR/shunit2/shunit2"
