# Pinned C 3.1.2 synchronization

`c312.json` is the reviewed behavior manifest. `c312-source.json` is generated
source inventory, not an approval record. Review totals are **645/2254 Core
units** and **142/373 CIU platform units**. The release check fails while source
hunks or required acceptance items remain unresolved.

G1–G9 retain baseline findings that predate the commit range. T1 records removal
of delivered extended CCID support as `removed intentional difference`; its
historical test assets remain available. T3 restores a functional NFC regression.
The five [USB correctness decisions](c312-correctness-decisions.md) preserve
Rust behavior where C is defective or unnecessarily couples shared storage.
Their 17 unequal cases remain excluded from parity totals. E63 WTX retry/cache
and physical/resource acceptance remain open.

## Review records

The inventory covers every pinned commit and each diff against **every parent**,
including merges. File metadata/binary changes and zero-context source hunks
have separate SHA-256 fingerprints. Repeated merge deltas make the final
resolution reviewable; inventory generation never assigns dispositions.
Inspect a pending hunk in the separate C repository with:

```sh
git diff --unified=0 PARENT COMMIT -- PATH
```

Each review maps numbered hunk fingerprints to behaviors. Each behavior records
target files, regression IDs, evidence scope/revision and SHA-256 values.
Changed inputs, absent artifacts, missing baseline rows, duplicate reviews or
nonexistent hunks are errors. Unmapped hunks and nonempty `remaining` entries
fail the release check. Implementation and acceptance are separate decisions.

From Core, validate the exact source objects and records:

```sh
python3 tests/check_c312_sync.py --source-repository /path/to/pinned-c-core
python3 -m unittest discover -s tests -p test_c312_sync.py -v
```

The CIU companion must also pass. From the platform root:

```sh
python3 tools/toolchain/rust/check-c312-sync.py \
  --c-platform-repository /path/to/pinned-c-platform \
  --c-core-repository /path/to/pinned-c-core
```

Ordinary CI uses `--structure-only` during the audit; its output explicitly
says **NOT release acceptance**. Release-tag CI runs the strict gate against
pinned C checkouts. No checker fetches refs, approves source units or compiles
`reference/legacy-c`. Portable fixtures are documented in
[testing](../testing/README.md#c-312-synchronization-gate).
