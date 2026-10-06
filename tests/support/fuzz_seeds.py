#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate seed corpus files for the apdu-fuzzer harness.

Seed files use the harness framing: [tag:u8][len:u16-LE][payload] records.
tag 0x00 = APDU, tag 0x01 = POWEROFF (len 0), tag 0x02 = storage fault
(payload [record_id, op]; op 0 = fail next write, 1 = fail next read).

Usage:
    fuzz_seeds.py OUTPUT_DIR [--import-legacy CORPUS_DIR ...]

Built-in seeds cover applet selection and representative commands per applet,
mixed with POWEROFF and storage-fault records. --import-legacy wraps each file
of a pre-migration raw corpus (hil-reports/fuzz/corpus-*) as one APDU record.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

TAG_APDU = 0x00
TAG_POWEROFF = 0x01
TAG_STORAGE_FAULT = 0x02

MAX_APDU_LEN = 4096  # fuzz.c FUZZ_MAX_APDU_LEN

# Applet SELECT APDUs (see tools/hil/blackbox_test.py APPLET_AIDS and the
# standard NDEF application AID).
SELECT_ADMIN = "00a4040005f000000000"
SELECT_OATH = "00a4040007a0000005272101"
SELECT_OPENPGP = "00a4040008d27600012401"
SELECT_PIV = "00a4040009a00000030800001000"
SELECT_FIDO = "00a4040008a0000006472f0001"
SELECT_NDEF = "00a4040007d2760000850101"

# Representative commands per applet; valid sequences borrow the known-good
# flows from tests/integration/replay_normal.py.
SINGLE_APDUS = [
    SELECT_ADMIN,
    SELECT_OATH,
    SELECT_OPENPGP,
    SELECT_PIV,
    SELECT_FIDO,
    SELECT_NDEF,
    "0020000006313233343536",  # admin: verify default PIN 123456
    "0043000000",  # admin: read config
    "0044010006020361626300",  # admin: write config
    "0041010030",  # admin: flash usage
    "00ca006e00",  # openpgp: application data
    "00ca00fa00",  # openpgp: algorithm attributes
    "00840000ff",  # openpgp: get challenge (255 bytes)
    "00cb3fff035c017e00",  # piv: discovery object
    "00f7010000",  # piv: metadata directory
    "80100000010400",  # fido: CTAP2 GetInfo
    "00c0000000",  # GET RESPONSE
    "0003000000",  # U2F VERSION with lc=0
    "0050000005" + "5245534554",  # admin factory reset "RESET" (rejected on host)
]

# Multi-record flows: (name, records). Records are ("apdu", hex),
# ("poweroff",) or ("fault", record_id, op).
FLOWS = [
    (
        "admin-pin-flow",
        [
            ("apdu", SELECT_ADMIN),
            ("apdu", "0020000006313233343536"),
            ("apdu", "0043000000"),
            ("apdu", "0044010006020361626300"),
            ("apdu", "0043000000"),
            ("poweroff",),
            ("apdu", SELECT_ADMIN),
            ("apdu", "0044010006020361626300"),
            ("apdu", "0020000006313233343536"),
            ("apdu", "0043000000"),
        ],
    ),
    (
        "fido-getinfo-chained",
        [
            ("apdu", SELECT_FIDO),
            ("apdu", "80100000010400"),
            ("apdu", "00c0000000"),
        ],
    ),
    (
        "oath-select-validate",
        [
            ("apdu", SELECT_OATH),
            ("apdu", "00a4000007" + "010a02000000"),  # SELECT with OATH version structure
            ("apdu", "0003000000"),
        ],
    ),
    (
        "openpgp-fault-read",
        [
            ("apdu", SELECT_OPENPGP),
            ("fault", 0x04, 1),  # fail next read of first openpgp state record
            ("apdu", "00ca006e00"),
            ("apdu", "00ca00fa00"),
        ],
    ),
    (
        "piv-fault-write",
        [
            ("apdu", SELECT_PIV),
            ("fault", 0x00, 0),  # fail next write of the versioned slot record
            ("apdu", "00f7010000"),
            ("poweroff",),
            ("apdu", SELECT_PIV),
            ("apdu", "00cb3fff035c017e00"),
        ],
    ),
    (
        "poweroff-storm",
        [
            ("poweroff",),
            ("poweroff",),
            ("apdu", SELECT_ADMIN),
            ("poweroff",),
            ("apdu", SELECT_FIDO),
            ("apdu", "80100000010400"),
            ("poweroff",),
        ],
    ),
]


def frame(tag: int, payload: bytes) -> bytes:
    return bytes((tag, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF)) + payload


def write_seed(out_dir: Path, name: str, content: bytes) -> None:
    digest = hashlib.sha1(content).hexdigest()
    path = out_dir / f"{name}-{digest[:12]}"
    path.write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory to write seed files into")
    parser.add_argument(
        "--import-legacy",
        type=Path,
        nargs="*",
        default=[],
        help="legacy raw-corpus directories; each file becomes one APDU record",
    )
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    count = 0

    for command in SINGLE_APDUS:
        write_seed(args.output, "apdu", frame(TAG_APDU, bytes.fromhex(command)))
        count += 1

    for name, records in FLOWS:
        content = b""
        for record in records:
            if record[0] == "apdu":
                content += frame(TAG_APDU, bytes.fromhex(record[1]))
            elif record[0] == "poweroff":
                content += frame(TAG_POWEROFF, b"")
            else:
                _, record_id, op = record
                content += frame(TAG_STORAGE_FAULT, bytes((record_id, op)))
        write_seed(args.output, name, content)
        count += 1

    skipped = 0
    for legacy_dir in args.import_legacy:
        for entry in sorted(legacy_dir.iterdir()):
            if not entry.is_file():
                continue
            blob = entry.read_bytes()
            if not blob or len(blob) > MAX_APDU_LEN:
                skipped += 1
                continue
            write_seed(args.output, "legacy", frame(TAG_APDU, blob))
            count += 1

    print(f"wrote {count} seed files to {args.output}" + (f" ({skipped} legacy entries skipped)" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
