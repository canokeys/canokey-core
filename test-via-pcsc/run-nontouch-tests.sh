#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
target="${1:-all}"

usage() {
    cat <<EOF
Usage: $0 [all|admin|oath|openpgp|piv|piv-enable-ext|piv-disable-ext]

Runs physical CanoKey PC/SC tests that do not require NFC or touch.
Each Go test file is compiled separately because the legacy files reuse helper names.
EOF
}

release_reader() {
    if command -v gpgconf >/dev/null 2>&1; then
        gpgconf --kill scdaemon >/dev/null 2>&1 || true
    fi
}

run_test() {
    local name="$1"
    local timeout="${2:-10m}"
    echo "===== $name ====="
    release_reader
    go test -v -count=1 -timeout "$timeout" "$SCRIPT_DIR/${name}_test.go"
}

run_admin() {
    CANOKEY_TEST_SKIP_NFC=1 CANOKEY_TEST_SKIP_TOUCH=1 run_test admin
}

run_openpgp() {
    echo "===== openpgp preflight reset ====="
    release_reader
    go test -v -count=1 -timeout 10m "$SCRIPT_DIR/openpgp_test.go" -run '^TestAppletReset$'
    run_test openpgp
}

run_piv_enable_ext() {
    CANOKEY_TEST_LEAVE_PIV_ALGO_EXT=1 \
        CANOKEY_TEST_PIV_ALGO_EXT_STANDARD=1 \
        CANOKEY_TEST_PIV_CONFIG_ONLY=1 \
        run_test piv
}

run_piv_disable_ext() {
    CANOKEY_TEST_PIV_ALGO_EXT_STANDARD=1 \
        CANOKEY_TEST_PIV_CONFIG_ONLY=1 \
        CANOKEY_TEST_PIV_ALGO_EXT_DISABLE=1 \
        run_test piv
}

case "$target" in
    all)
        run_admin
        run_test oath 30m
        run_openpgp
        run_test piv
        ;;
    admin)
        run_admin
        ;;
    oath)
        run_test oath 30m
        ;;
    openpgp)
        run_openpgp
        ;;
    piv)
        run_test piv
        ;;
    piv-enable-ext)
        run_piv_enable_ext
        ;;
    piv-disable-ext)
        run_piv_disable_ext
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
