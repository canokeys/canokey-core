#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute literal CCID/NFC/WebUSB events through pinned C and Rust transports.

Requires a separate local C checkout and its pinned dependencies. Compiles no
legacy snapshot. The C adapter reuses unchanged release test initialization and
intercepts only dummy USB output; CCID, routing and applets are real. Rust uses
the existing USB-session fixture's endpoint/mailbox/transport composition.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
REVISION = "a349b268e12953dd85169e9649091c4f91ce7c68"
DEPENDENCIES = {
    "canokey-crypto": "f9382dc23ea330521ad0874b669826702fea790b",
    "littlefs": "6cb4e86540eca0d9ba62500a298385c9d863c8be",
    "tinycbor": "6442e749ca811e24afad1551338a45c75e09808f",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(arguments, **kwargs):
    return subprocess.run(arguments, check=True, text=True, **kwargs)


def build_c(source, build, log):
    source, build = source.resolve(), build.resolve()
    assert "reference/legacy-c" not in str(source)
    for path, revision in [(source, REVISION)] + [
        (source / name, revision) for name, revision in DEPENDENCIES.items()
    ]:
        actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
        if actual != revision:
            raise RuntimeError(f"wrong pinned source: {path}: {actual}")
    # Ignore the expected configured Ed25519 patch in the separate PSA subtree.
    command(["git", "-C", str(source), "diff", "--exit-code", "HEAD", "--",
             "src", "interfaces", "applets", "include", "test", "virt-card",
             "CMakeLists.txt", "cmake", "scripts"], stdout=log, stderr=subprocess.STDOUT)
    command(["cmake", "-S", str(source), "-B", str(build), "-G", "Unix Makefiles",
             "-DENABLE_TESTS=ON", "-DENABLE_DEBUG_OUTPUT=OFF", "-DCMAKE_BUILD_TYPE=Debug",
             # CIU uses short enums; otherwise the host key metadata enlarges
             # sizeof(ck_key_t) and changes the protocol's request capacity.
             "-DCMAKE_C_FLAGS=-fshort-enums",
             "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], stdout=log, stderr=subprocess.STDOUT)
    command(["cmake", "--build", str(build), "--target", "test_apdu", "--parallel", "4"],
            stdout=log, stderr=subprocess.STDOUT)
    commands = json.loads((build / "compile_commands.json").read_text())

    def compile_object(original, replacement, output, extra=()):
        entry = next(item for item in commands if Path(item["file"]) == original)
        arguments = entry.get("arguments") or shlex.split(entry["command"])
        arguments[arguments.index("-o") + 1] = str(output)
        arguments[arguments.index("-c") + 1] = str(replacement)
        command(arguments + list(extra), cwd=entry["directory"], stdout=log, stderr=subprocess.STDOUT)

    adapter = build / "c312-wire-adapter"
    adapter.mkdir(exist_ok=True)
    pinned = source / "test/test_apdu.c"
    text = pinned.read_text()
    initialization = text[text.index("int main() {"):text.index("  const struct CMUnitTest tests[] = {", text.index("int main() {"))]
    # The release's unchanged initialization keeps the filesystem configuration
    # alive on main's stack for the entire packet replay, as in the original test.
    unit = ("#define main c312_original_suite_main\n#include " + json.dumps(str(pinned)) +
            "\n#undef main\n#include " + json.dumps(str(ROOT / "tests/support/c312_ccid.c")) +
            "\n" + initialization +
            "  portable_ccid_loop();\n  lfs_filebd_destroy(&cfg);\n  return 0;\n}\n")
    (adapter / "runner.c").write_text(unit)
    compile_object(pinned, adapter / "runner.c", adapter / "runner.o")
    # Recompiled adapter control flow invalidates its old coverage counters.
    (adapter / "runner.gcda").unlink(missing_ok=True)
    dummy = source / "virt-card/usb-dummy.c"
    compile_object(dummy, dummy, adapter / "dummy.o", ["-DUSBD_LL_Transmit=portable_dummy_transmit"])
    arguments = shlex.split((build / "test/CMakeFiles/test_apdu.dir/link.txt").read_text())
    arguments[arguments.index("-o") + 1] = str(adapter / "runner")
    for index, argument in enumerate(arguments):
        if argument.endswith("/test_apdu.c.o"):
            arguments[index] = str(adapter / "runner.o")
        elif argument.endswith("/virt-card/usb-dummy.c.o"):
            arguments[index] = str(adapter / "dummy.o")
    command(arguments, cwd=build / "test", stdout=log, stderr=subprocess.STDOUT)
    return adapter / "runner"


def execute(executable, case, rust):
    lines = []
    nfc = case.get("transport") == "nfc"
    include_hid = case.get("transport") == "usb"
    webusb = include_hid or case.get("transport") == "webusb"
    # Select the adapter before the first event, including a leading tick.
    # This is fixture initialization, not an observed wire event.
    if webusb and not rust:
        if case.get("ctap_pin_retries") is not None:
            assert include_hid and case["ctap_pin_retries"] == 8
            lines.append("USB-RETRIES8")
        else:
            lines.append("USB" if include_hid else "WEBUSB")
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
    with tempfile.TemporaryDirectory(prefix="c312-wire-run-") as directory:
        mode = "--c312-usb-wire" if include_hid else "--c312-webusb-wire" if webusb else ("--c312-nfc-wire" if nfc else "--c312-wire")
        result = subprocess.run([str(executable)] + ([mode] if rust else []),
                                input="\n".join(lines) + "\n", cwd=directory,
                                capture_output=True, text=True, timeout=30)
    actual = [line[5:].strip() for line in result.stdout.splitlines() if line.startswith("WIRE ")]
    if any("expected_c" in step for step in case["steps"]):
        validate_difference(case)
        for step in case["steps"]:
            value = step.get("expected_c", step["expected"])
            if value != "STALL":
                bytes.fromhex(value)
    expected = [step["expected"] if rust else step.get("expected_c", step["expected"])
                for step in case["steps"]]
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
        expected_reports = [step.get("expected_hid_c", step.get("expected_hid", ""))
                            if not rust else step.get("expected_hid", "")
                            for step in case["steps"]]
        if any("expected_hid_c" in step for step in case["steps"]):
            validate_difference(case)
        for value in expected_reports:
            assert len(bytes.fromhex(value)) % 64 == 0
        comparison["hid_reports"] = reports
        comparison["passed"] &= reports == expected_reports
    return comparison


def validate_difference(case):
    difference = case.get("difference", {})
    disposition = difference.get("disposition")
    assert disposition in ("unresolved", "intentional difference")
    if disposition == "intentional difference":
        # A named, reviewable decision is required; outputs remain literal and
        # unequal cases never enter parity totals, regardless of disposition.
        decision = Path(difference["decision"])
        assert not decision.is_absolute() and '..' not in decision.parts
        assert (ROOT / decision).is_file() and difference["reason"].strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-repository", type=Path)
    parser.add_argument("--c-build", type=Path)
    parser.add_argument("--rust-only", action="store_true",
                        help="Replay archived literal expectations in ordinary Rust CI; not a new C comparison")
    parser.add_argument("--rust-runner", type=Path, required=True)
    parser.add_argument("--vectors", type=Path, default=ROOT / "tests/fixtures/c312-ccid/vectors.json")
    parser.add_argument("--output", type=Path, default=ROOT / "tests/fixtures/c312-ccid/report.json")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    c_runner = None
    if not args.rust_only:
        if args.c_repository is None or args.c_build is None:
            parser.error("C comparison requires --c-repository and --c-build")
        with args.output.with_suffix(".build.log").open("w") as log:
            c_runner = build_c(args.c_repository, args.c_build, log)
    vectors = json.loads(args.vectors.read_text())
    results = []
    identities = set()
    for case in vectors["cases"]:
        assert case["id"] not in identities
        identities.add(case["id"])
        result = {"id": case["id"], "oracle_rows": case["oracle_rows"],
                  "rust": execute(args.rust_runner.resolve(), case, True)}
        if c_runner is not None:
            result["c"] = execute(c_runner, case, False)
            result["wire_equal"] = all(result["c"].get(key) == result["rust"].get(key)
                                       for key in ("responses", "bulk_responses", "hid_reports"))
        if "difference" in case:
            result["difference"] = case["difference"]
        results.append(result)
        if not result["rust"]["passed"] or (c_runner is not None and not result["c"]["passed"]):
            print(json.dumps({"failure": result,
                              "expected_rust": [step["expected"] for step in case["steps"]],
                              "expected_c": [step.get("expected_c", step["expected"])
                                             for step in case["steps"]]}))
    report = {"revision": REVISION, "dependencies": DEPENDENCIES,
              "mode": "rust-only" if args.rust_only else "pinned-c-and-rust",
              "scope": vectors["scope"], "vectors_sha256": digest(args.vectors),
              "c_adapter_sha256": digest(ROOT / "tests/support/c312_ccid.c"),
              "c_webusb_adapter_sha256": digest(ROOT / "tests/support/c312_webusb.c"),
              "rust_adapter_sha256": digest(ROOT / "tests/card/src/bin/usb_sessions/portable.rs"),
              "rust_nfc_adapter_sha256": digest(ROOT / "tests/card/src/bin/usb_sessions/portable_nfc.rs"),
              "rust_webusb_adapter_sha256": digest(ROOT / "tests/card/src/bin/usb_sessions/portable_webusb.rs"),
              "c_executable_sha256": digest(c_runner) if c_runner is not None else None,
              "rust_executable_sha256": digest(args.rust_runner),
              "compiler": subprocess.check_output(["cc", "--version"], text=True).splitlines()[0],
              "c_enum_flags": ["-fshort-enums"], "asserted_c_request_bytes": 1296,
              "results": results}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    passed = sum(result["rust"]["passed"] and
                 (c_runner is None or result["c"]["passed"]) for result in results)
    label = "Rust archived expectations" if args.rust_only else "Pinned C/Rust portable transport vectors"
    print(f"{label}: {passed}/{len(results)} passed")
    differences = [result for result in results if result.get("difference")]
    if differences:
        for disposition in ("unresolved", "intentional difference"):
            count = sum(row["difference"]["disposition"] == disposition for row in differences)
            if count:
                print(f"Explicit {disposition}: {count}; excluded from wire-parity claims")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
