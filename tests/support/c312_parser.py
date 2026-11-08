#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute six unchanged pinned C CTAP parsers with instrumented request sources.

The adapter uses the pinned test filesystem/crypto initialization. It also runs
the unchanged exact-RP response regression. Parser vectors are separately
consumed by Rust at every fragment boundary; source failure/cancellation is C
evidence only, not an assertion of Rust or physical transport parity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

from fido2 import cbor
from c312_ccid import ROOT, REVISION, build_c, command, digest


def build_parser(source, build, log):
    build_c(source, build, log)  # Verifies pinned source/dependencies and builds unchanged libraries.
    commands = json.loads((build / "compile_commands.json").read_text())
    pinned = source / "test/test_apdu.c"
    entry = next(e for e in commands if Path(e["file"]).resolve() == pinned)
    adapter = build / "c312-parser-adapter"
    adapter.mkdir(exist_ok=True)
    text = pinned.read_text()
    start = text.index("int main() {")
    initialization = text[start:text.index("  const struct CMUnitTest tests[] = {", start)]
    unit = ("#define main c312_original_suite_main\n#include " + json.dumps(str(pinned)) +
            "\n#undef main\n#include " + json.dumps(str(ROOT / "tests/support/c312_parser.c")) +
            "\n" + initialization +
            "  portable_parser_loop();\n  lfs_filebd_destroy(&cfg);\n  return 0;\n}\n")
    (adapter / "runner.c").write_text(unit)
    arguments = entry.get("arguments") or shlex.split(entry["command"])
    arguments[arguments.index("-o") + 1] = str(adapter / "runner.o")
    arguments[arguments.index("-c") + 1] = str(adapter / "runner.c")
    command(arguments, cwd=entry["directory"], stdout=log, stderr=subprocess.STDOUT)
    (adapter / "runner.gcda").unlink(missing_ok=True)
    arguments = shlex.split((build / "test/CMakeFiles/test_apdu.dir/link.txt").read_text())
    arguments[arguments.index("-o") + 1] = str(adapter / "runner")
    arguments = [str(adapter / "runner.o") if x.endswith("/test_apdu.c.o") else x for x in arguments]
    command(arguments, cwd=build / "test", stdout=log, stderr=subprocess.STDOUT)
    return adapter / "runner"


def vectors():
    schemas = {
        1: {1: b"h" * 32, 2: {"id": "example.com"}, 3: {"id": b"u"},
            4: [{"alg": -7, "type": "public-key"}]},
        2: {1: "example.com", 2: b"h" * 32},
        # Supply management auth fields: C checks missing authorization inside
        # its parser, while Rust checks it later during command execution.
        6: {2: 1}, 10: {1: 1, 3: 1, 4: b"a" * 16}, 12: {1: 1, 3: 0}, 13: {1: 3},
    }
    for opcode, schema in schemas.items():
        yield dict(id=f"{opcode}-base", command=opcode, body=cbor.encode(schema).hex())
        # Long unknown text keys must be skipped, independently of value length.
        yield dict(id=f"{opcode}-long-key", command=opcode,
                   body=cbor.encode(schema | {"?" * 256: "x" * 256}).hex())
        if opcode in [1, 2]:
            locations = [2, 3, 6, 7] if opcode == 1 else [4, 5]
            for location in locations:
                nested = dict(schema.get(location, {})) | {"?" * 256: "x" * 256}
                yield dict(id=f"{opcode}-nested{location}-long-key", command=opcode,
                           body=cbor.encode(schema | {location: nested}).hex())
                for size in [31, 32, 33, 256]:
                    value = True if location == (7 if opcode == 1 else 5) else "x"
                    nested = dict(schema.get(location, {})) | {"?" * size: value}
                    yield dict(id=f"{opcode}-nested{location}-key{size}", command=opcode,
                               body=cbor.encode(schema | {location: nested}).hex())
                if location in ([2, 7] if opcode == 1 else [5]):
                    nested = dict(schema.get(location, {})) | {"?": 0}
                    yield dict(id=f"{opcode}-nested{location}-wrong-value", command=opcode,
                               body=cbor.encode(schema | {location: nested}).hex())
            # Both names exceed the bounded key window and differ after it.
            nested = {"?" * 255 + "a": "x", "?" * 255 + "b": "y"}
            location = 6 if opcode == 1 else 4
            yield dict(id=f"{opcode}-same-prefix-long-keys", command=opcode,
                       body=cbor.encode(schema | {location: nested}).hex())
        else:
            # Exceeds the old largeBlobs-derived string window (1232), while
            # remaining inside the1296-byte logical request budget.
            for leaf in ["x" * 1240, b"x" * 1240]:
                yield dict(id=f"{opcode}-{type(leaf).__name__}-wide-string", command=opcode,
                           body=cbor.encode(schema | {127: leaf}).hex())
        for depth in [0, 1, 3, 4, 5, 8, 9]:
            for shape in ["array", "map", "mixed"]:
                for leaf in [0, "x" * 256, bytes(range(256))]:
                    value = leaf
                    for level in range(depth):
                        value = {0: value} if shape == "map" or (shape == "mixed" and level % 2) else [value]
                    # Integer keys exercise top-level unknown dispatch in all six parsers.
                    raw = cbor.encode(schema | {127: value})
                    yield dict(id=f"{opcode}-{depth}-{shape}-{type(leaf).__name__}",
                               command=opcode, body=raw.hex())
        # Malformed unknown string bodies are distinct from transport read failure.
        raw = cbor.encode(schema | {127: b"x" * 256})
        yield dict(id=f"{opcode}-truncated-string", command=opcode, body=raw[:-1].hex())
        yield dict(id=f"{opcode}-invalid-value", command=opcode,
                   body=(cbor.encode(schema | {127: 0})[:-1] + b"\xff").hex())


def execute(runner, cases):
    lines = [f"{v['command']} {mode} {trigger} {v['body']}" for v, mode, trigger in cases]
    with tempfile.TemporaryDirectory(prefix="c312-parser-run-") as directory:
        result = subprocess.run([str(runner)], input="\n".join(lines) + "\n", text=True,
                                capture_output=True, cwd=directory, check=True)
    assert "RP_EXACT cases=4 passed" in result.stdout
    assert not result.stderr.strip(), result.stderr
    rows = [tuple(map(int, line.split()[1:])) for line in result.stdout.splitlines()
            if line.startswith("RESULT ")]
    assert len(rows) == len(cases), (result.stdout, len(cases))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-repository", type=Path, required=True)
    parser.add_argument("--c-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "tests/fixtures/c312-parser")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "build.log").open("w") as log:
        runner = build_parser(args.c_repository.resolve(), args.c_build.resolve(), log)
    inputs = list(vectors())
    baseline = execute(runner, [(v, mode, 0) for v in inputs for mode in [0, 5]])
    for i, vector in enumerate(inputs):
        source, memory = baseline[2 * i:2 * i + 2]
        assert source[0] == memory[0], (vector["id"], source, memory)
        vector.update(status=source[0], source_reads=source[1], largest_read=source[4])
    faults = []
    for vector in inputs:
        # Every reached read of each valid long-string schema; malformed bodies
        # additionally exercise cancellation overriding an existing parser error.
        if vector["id"].endswith(("long-key", "wide-string", "truncated-string", "invalid-value")):
            faults.append((vector, 4, 0))
            for read in range(1, vector["source_reads"] + 1):
                faults.extend((vector, mode, read) for mode in [1, 2, 3])
    results = execute(runner, faults)
    records = []
    for (vector, mode, trigger), row in zip(faults, results):
        status, reads, failures, cancelled, largest = row
        if mode == 1:
            # A transient C reader failure can be retried/ignored. Preserve its
            # actual result instead of treating C as a fail-closed oracle.
            assert failures == 1 and not cancelled, (vector["id"], mode, trigger, row)
        else:
            assert cancelled and status == 0x2d, (vector["id"], mode, trigger, row)
        records.append(dict(id=vector["id"], mode=mode, trigger=trigger, status=status,
                            reads=reads, failures=failures, cancelled=bool(cancelled), largest_read=largest))
    paths = ["applets/ctap/ctap-parser.c", "applets/ctap/ctap-parser.h",
             "applets/ctap/ctap-internal.h", "include/applet-scratch.h", "test/test_apdu.c"]
    source_hashes = {p: hashlib.sha256(subprocess.check_output(
        ["git", "-C", str(args.c_repository), "show", f"{REVISION}:{p}"])).hexdigest() for p in paths}
    report = dict(revision=REVISION,
                  scope="Unchanged six C CTAP parsers, contiguous/source status comparison and callback fault/cancellation sweep; unchanged exact-RP response test. No USB/RF or Rust cancellation parity.",
                  runner_sha256=digest(runner), inputs=source_hashes,
                  adapters={p: digest(ROOT / p) for p in ["tests/support/c312_parser.c", "tests/support/c312_parser.py", "tests/support/c312_ccid.py"]},
                  parser_executions=len(baseline) + len(results), exact_rp_cases_per_run=4,
                  read_failure_successes=sum(r["mode"] == 1 and r["status"] == 0 for r in records),
                  source_modes={"0": "normal", "1": "read failure", "2": "cancel and fail read",
                                "3": "cancel and complete read", "4": "cancel before parsing", "5": "contiguous"},
                  vectors=inputs, faults=records)
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    rust = ["// Generated by tests/support/c312_parser.py; real pinned C CTAP parsers.",
            "const C312_PARSER_VECTORS: &[(&str, &[u8], u8)] = &["]
    for v in inputs:
        wire = bytes([v["command"]]) + bytes.fromhex(v["body"])
        literal = "".join(f"\\x{b:02x}" for b in wire)
        rust.append(f'    ("{v["id"]}", b"{literal}", {v["status"]}),')
    rust.append("];\n")
    (args.output / "vectors.rs").write_text("\n".join(rust))
    print(f"C CTAP parsers: {len(inputs)} vectors, {len(baseline) + len(results)} executions; {len(results)} source faults/cancellations; exact-RP response4 cases/run")


if __name__ == "__main__":
    main()
