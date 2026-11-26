#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay literal CCID, NFC and USB events through the Rust test card."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(executable, case):
    lines = []
    nfc = case.get("transport") == "nfc"
    include_hid = case.get("transport") == "usb"
    webusb = include_hid or case.get("transport") == "webusb"
    for step in case["steps"]:
        if webusb and "tick" not in step:
            operation = next(key for key in ("setup", "out", "in", "poll", "ccid", "hid", "reset",
                                            "class_ccid", "class_hid") if key in step)
            value = step[operation] if operation in ("setup", "out", "ccid", "hid",
                                                    "class_ccid", "class_hid") else ""
            data = bytes.fromhex(value)
            assert len(data) <= (64 if operation in ("ccid", "hid", "class_ccid", "class_hid") else 16)
            if operation == "setup":
                assert len(data) == 8
            if operation == "reset":
                assert step["reset"] is True
            assert isinstance(step.get("service", True), bool)
            lines.append(("" if step.get("service", True) else "DEFER ") + operation.upper() + " " + value)
        elif nfc and "poll" in step:
            assert step["poll"] is True
            lines.append("POLL 0")
        elif "irq" in step:
            assert nfc
            flags = bytes.fromhex(step["irq"])
            status = bytes.fromhex(step["rf_status"])
            packet = bytes.fromhex(step.get("packet", ""))
            assert len(flags) == 3 and len(status) == 1 and len(packet) <= 32
            lines.append("IRQ " + (flags + status + packet).hex())
        elif "packet" in step:
            packet = bytes.fromhex(step["packet"])
            assert (0 < len(packet) <= 32) if nfc else (0 < len(packet) <= 64)
            lines.append(("NFC " if nfc else "CCID ") + packet.hex())
        elif "halt" in step:
            assert nfc and step["halt"] is True
            lines.append("HALT 0")
        else:
            assert isinstance(step["tick"], int) and 0 <= step["tick"] <= 0xffffffff
            lines.append("TICK " + str(step["tick"]))
        if nfc:
            assert isinstance(step.get("service", True), bool)
            if not step.get("service", True):
                lines[-1] = "DEFER " + lines[-1]
        if step["expected"] != "STALL":
            bytes.fromhex(step["expected"])
    with tempfile.TemporaryDirectory(prefix="wire-run-") as directory:
        mode = "--usb-wire" if include_hid else "--webusb-wire" if webusb else ("--nfc-wire" if nfc else "--ccid-wire")
        result = subprocess.run([str(executable)] + [mode],
                                input="\n".join(lines) + "\n", cwd=directory,
                                capture_output=True, text=True, timeout=30)
    actual = [line[5:].strip() for line in result.stdout.splitlines() if line.startswith("WIRE ")]
    expected = [step["expected"] for step in case["steps"]]
    comparison = {"passed": result.returncode == 0 and actual == expected,
                  "returncode": result.returncode, "responses": actual,
                  "stderr": result.stderr if result.returncode else ""}
    if webusb:
        bulk = [line[5:].strip() for line in result.stdout.splitlines() if line.startswith("BULK ")]
        expected_bulk = [step.get("expected_ccid", "") for step in case["steps"]]
        for value in expected_bulk:
            bytes.fromhex(value)
        comparison["passed"] &= bulk == expected_bulk
        if any(bulk) or any(expected_bulk):
            comparison["bulk_responses"] = bulk
    if include_hid:
        reports = [line[4:].strip() for line in result.stdout.splitlines() if line.startswith("HID ")]
        expected_reports = [step.get("expected_hid", "") for step in case["steps"]]
        for value in expected_reports:
            assert len(bytes.fromhex(value)) % 64 == 0
        comparison["hid_reports"] = reports
        comparison["passed"] &= reports == expected_reports
    return comparison


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-runner", type=Path, required=True)
    parser.add_argument("--vectors", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runner = args.rust_runner.resolve()
    vectors = json.loads(args.vectors.read_text())
    results = {}
    for case in vectors["cases"]:
        case_id = case["id"]
        assert case_id not in results, case_id
        result = execute(runner, case)
        results[case_id] = result
        if not result["passed"]:
            print(json.dumps({"case": case_id, "observed": result, "steps": case["steps"]}))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    passed = sum(result["passed"] for result in results.values())
    print(f"{args.vectors.parent.name}: {passed}/{len(results)} cases passed")
    return 0 if results and passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
