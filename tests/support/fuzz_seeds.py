#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate framed seeds, optionally validating baseline paths with --replay.

Normal commands have SELECT context and expected status/data checks. Imported
legacy mutations are coverage inputs, not validated applet-path baselines.
--refresh-builtins replaces only previously generated named seeds.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

from replay_events import MAX_APDU_LEN, TAGS, frame, replay_command

# ISO 7816 SELECT with exact AID lengths, shared with baseline checks.
SELECT_ADMIN = "00a4040005f000000000"
SELECT_OATH = "00a4040007a0000005272101"
SELECT_OPENPGP = "00a4040006d27600012401"
SELECT_PIV = "00a4040009a00000030800001000"
SELECT_FIDO = "00a4040008a0000006472f0001"
SELECT_NDEF = "00a4040007d2760000850101"


def apdu(command):
    return ("apdu", bytes.fromhex(command))


# Expected SW values include deliberate authorization and stale-response probes.
BASELINES = [
    ("admin-pin-flow", [apdu(SELECT_ADMIN), apdu("0020000006313233343536"),
      apdu("0043000000"), apdu("0044010006020361626300"), apdu("0043000000"),
      ("poweroff", b""), apdu(SELECT_ADMIN), apdu("0044010006020361626300"),
      apdu("0020000006313233343536"), apdu("0043000000")],
     [0x9000, 0x9000, 0x9000, 0x9000, 0x9000, None, 0x9000, 0x6982, 0x9000, 0x9000]),
    ("fido-getinfo-chained", [apdu(SELECT_FIDO), apdu("80100000010400"), apdu("00c0000000")],
     [0x9000, 0x9000, 0x6986]),
    ("fido-response-lease", [apdu(SELECT_FIDO), ("apdu_raw", bytes.fromhex("80100000010400")),
      ("poweroff", b""), apdu("00c0000000")], [0x9000, 0x6100, None, 0x6986]),
    ("openpgp-discovery", [apdu(SELECT_OPENPGP), apdu("00ca006e00"), apdu("00ca00fa00")],
     [0x9000] * 3),
    ("piv-discovery", [apdu(SELECT_PIV), apdu("00cb3fff035c017e00"), apdu("00f7010000")],
     [0x9000] * 3),
    ("oath-list", [apdu(SELECT_OATH), apdu("00a1000000")], [0x9000] * 2),
    ("ndef-capability", [apdu(SELECT_NDEF), apdu("00a4000c02e103"), apdu("00b000000f")],
     [0x9000] * 3),
    ("poweroff-storm", [("poweroff", b""), ("poweroff", b""), apdu(SELECT_ADMIN),
      ("poweroff", b""), apdu(SELECT_FIDO), apdu("80100000010400"), ("poweroff", b"")],
     [None, None, 0x9000, None, 0x9000, 0x9000, None]),
    ("runtime-reset", [apdu(SELECT_ADMIN), apdu("0020000006313233343536"),
      ("reset", b""), apdu(SELECT_ADMIN), apdu("0043000000")],
     [0x9000, 0x9000, None, 0x9000, 0x6982]),
]

# A fault armed before SELECT must be consumed by the targeted repository read.
FAULT_CASES = [
    ("openpgp-fault-read", [("storage_fault", bytes([0x04, 1])), apdu(SELECT_OPENPGP),
      apdu(SELECT_OPENPGP)], [None, 0x6900, 0x9000]),
]


def validate_baselines(binary):
    for name, events, expected in BASELINES + FAULT_CASES:
        commands = [replay_command(event) for event in events]
        result = subprocess.run([str(binary)], input="\n".join(commands) + "\n",
                                text=True, capture_output=True, check=True, timeout=30)
        replies = result.stdout.splitlines()
        assert replies[0] == "READY" and len(replies) == len(events) + 1, (name, result.stdout)
        data = []
        for reply, sw in zip(replies[1:], expected):
            if sw is None:
                assert reply == "OK", (name, reply)
                data.append(b"")
            else:
                assert re.fullmatch(r"RESP [0-9A-F]{4}(?:[0-9A-F]{2})*", reply), (name, reply)
                actual = int(reply[5:9], 16)
                # 61xx is a remaining-length hint, not a fixed response-size oracle.
                assert (actual & 0xFF00 == sw if sw == 0x6100 else actual == sw), (name, reply, hex(sw))
                data.append(bytes.fromhex(reply[9:]))
        if name == "fido-getinfo-chained":
            assert data[0] == b"U2F_V2" and data[1][0] == 0 and len(data[1]) > 256
        elif name == "openpgp-discovery":
            assert data[1].startswith(b"\x6e") and data[2].startswith(b"\xfa")
        elif name == "piv-discovery":
            assert data[0].startswith(b"\x61") and data[1].startswith(b"\x7e")
        elif name == "oath-list":
            assert data[0].startswith(b"\x79") and data[1] == b""
        elif name == "ndef-capability":
            assert len(data[2]) == 15
        elif name == "admin-pin-flow":
            assert data[4] == data[-1] == bytes.fromhex("020000")
        print(f"baseline {name}: {len(events)} expected steps passed")


def write_seed(directory, name, content):
    digest = hashlib.sha1(content).hexdigest()
    (directory / f"{name}-{digest[:12]}").write_bytes(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--refresh-builtins", action="store_true")
    parser.add_argument("--import-legacy", type=Path, nargs="*", default=[])
    args = parser.parse_args()
    if args.validate_only and not args.replay:
        parser.error("--validate-only requires --replay")
    if args.replay:
        validate_baselines(args.replay)
    if args.validate_only:
        return
    if not args.output:
        parser.error("output directory required")
    args.output.mkdir(parents=True, exist_ok=True)
    if args.refresh_builtins:
        prefixes = {name for name, _, _ in BASELINES + FAULT_CASES}
        prefixes.update(["apdu", "oath-select-validate", "piv-fault-write"])
        for entry in args.output.iterdir():
            # Preserve imported/hash-named mutations; replace superseded built-ins only.
            if entry.is_file() and any(re.fullmatch(re.escape(prefix) + r"-[0-9a-f]{12}", entry.name)
                                       for prefix in prefixes):
                entry.unlink()
    reverse_tags = {name: tag for tag, name in TAGS.items()}
    for name, events, _ in BASELINES + FAULT_CASES:
        write_seed(args.output, name, b"".join(frame(reverse_tags[kind], payload)
                                             for kind, payload in events))
    for directory in args.import_legacy:
        for entry in sorted(directory.iterdir()):
            if entry.is_file() and 0 < entry.stat().st_size <= MAX_APDU_LEN:
                write_seed(args.output, "legacy", frame(0x00, entry.read_bytes()))
    print(f"generated {len(BASELINES) + len(FAULT_CASES)} built-in seeds; "
          f"baseline validation={'passed' if args.replay else 'not run'}")


if __name__ == "__main__":
    main()
