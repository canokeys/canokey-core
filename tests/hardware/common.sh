#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

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
