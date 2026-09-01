#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This script is intended to run on macOS." >&2
    exit 1
fi

TEST_REAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LANGUAGE=en_US
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export USER="${USER:-$(id -nu)}"

die() {
    echo "error: $*" >&2
    exit 1
}

find_cmd() {
    local name
    for name in "$@"; do
        if command -v "$name" >/dev/null 2>&1; then
            command -v "$name"
            return 0
        fi
    done
    return 1
}

require_cmd() {
    local name
    for name in "$@"; do
        if command -v "$name" >/dev/null 2>&1; then
            return 0
        fi
    done
    die "missing required command: $*"
}

require_file() {
    [[ -f "$1" ]] || die "missing required file: $1"
}

macos_mk_private_dir() {
    local dir="$1"
    rm -rf "$dir"
    mkdir -p "$dir"
    chmod 700 "$dir"
}

macos_stop_user_processes() {
    local proc
    for proc in "$@"; do
        pkill -u "$(id -u)" -x "$proc" >/dev/null 2>&1 || true
    done
}

macos_timestamp() {
    date -u "+%Y-%m-%dT%H:%M:%SZ"
}

macos_find_piv_reader() {
    local tool="${YUBICO_PIV_TOOL:-yubico-piv-tool}"
    "$tool" -r "" -a list-readers 2>/dev/null | awk '
        NF == 0 { next }
        {
            line = $0
            lower = tolower(line)
            if (lower ~ /canokey/ || lower ~ /piv/ || lower ~ /yubikey/) {
                print line
                found = 1
                exit
            }
            if (first == "") {
                first = line
            }
        }
        END {
            if (!found && first != "") {
                print first
            }
        }'
}

macos_find_opensc_pkcs11_module() {
    local candidate
    if [[ -n "${OPENSC_PKCS11_MODULE:-}" ]]; then
        [[ -f "$OPENSC_PKCS11_MODULE" ]] && echo "$OPENSC_PKCS11_MODULE"
        return 0
    fi

    for candidate in \
        /Library/OpenSC/lib/opensc-pkcs11.so \
        /opt/homebrew/lib/opensc-pkcs11.so \
        /usr/local/lib/opensc-pkcs11.so \
        /opt/local/lib/opensc-pkcs11.so
    do
        if [[ -f "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
}
