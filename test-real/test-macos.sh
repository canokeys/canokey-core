#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
target="${1:-all}"
if [[ $# -gt 0 ]]; then
    shift
fi

usage() {
    cat <<EOF
Usage: $0 [all|gpg|piv]
       $0 gpg [test_name ...]
       $0 piv [test_name ...]

Environment overrides:
  GPG_BIN=/path/to/gpg
  OPENSSL_BIN=/path/to/openssl
  YUBICO_PIV_TOOL=/path/to/yubico-piv-tool
  OPENSC_PKCS11_MODULE=/path/to/opensc-pkcs11.so
  RDID='reader name'
  PKCS11_SLOT='slot id'
EOF
}

case "$target" in
    all)
        "$SCRIPT_DIR/test-macos-gpg.sh" "$@"
        "$SCRIPT_DIR/test-macos-piv.sh" "$@"
        ;;
    gpg)
        "$SCRIPT_DIR/test-macos-gpg.sh" "$@"
        ;;
    piv)
        "$SCRIPT_DIR/test-macos-piv.sh" "$@"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
