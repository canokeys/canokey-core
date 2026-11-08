# Pinned C 3.1.2 synchronization

`c312.json` is the reviewed behavior manifest. `c312-source.json` is generated
source inventory, not an approval record. The current release check **fails**:
source-hunk reviews and the listed transport/device acceptance are unfinished.
G1-G9 remain separate baseline findings even when they predate the commit range.
T1 explicitly records removal of delivered extended CCID as
`removed intentional difference`; its historical assets remain reproducible.
T3 is restoration of a functional NFC regression.

Current reviewed units:585/2254 Core and142/373 CIU platform. The latest fourteen
transport suites execute365 cases/11695 events on pinned C and Rust, with348
equal-output cases and no response normalization. L8/E35 stale output,
C1-RETRIES/E39 fresh retry counts, CID1/E43 cross-CID disclosure,
U3/E47 GET_STATUS validation and U4/E48 busy-descriptor replies remain
unresolved (17 cases); fixture preconditions are explicit. Host CTests pass42/42.
E30/E31 separate completed WebUSB expiry
and byte-stage abort from applet-context reset. Rust-only sessions additionally
check cancelled foreign reservation and pending-output contention after expiry. See
[wire reproduction](../../tests/fixtures/c312-ccid/README.md).
T2/T4/T5/T7/T8/L2/L5/L6/L7 and implicit-Le validation now have individual records;
the NFC follow-up identifier rename has an exact transformation proof.
Unexecuted matrix portions and physical acceptance remain explicit blockers.
USB control source review adds91 units from13 parent/file diffs. E46 tests
directional HALT/status/clear and rejection/recovery; the Rust feature matrix
checks absent endpoints and driver dispatch on repeated clear. This does not
prove physical DATA-toggle effects. E48 checks exact source preservation after
descriptor requests, with C/Rust reply differences separately retained. See
[control comparison](../../tests/fixtures/c312-usb-control/README.md).

The inventory contains the complete pinned commit range and each commit's diff
against **every parent**, including merge results. File metadata/binary changes
and zero-context source hunks have separate SHA256 fingerprints. Duplicate
merge deltas are intentional: they make the final resolution reviewable without
assuming a merge only contains its children. The generator never assigns a
disposition. To inspect a pending hunk, use the recorded commit, parent and path
with `git diff --unified=0 PARENT COMMIT -- PATH` in the separate C repository.

Each review maps specific numbered hunk fingerprints to concrete behaviors.
Each behavior records target files, regression IDs, evidence scope/revision and
SHA256 values. Changed inputs, absent artifacts, missing baseline rows, duplicate
reviews and nonexistent source hunks are errors. Unmapped hunks or nonempty
`remaining` entries fail the default release check. An implementation disposition
can have unfinished acceptance; it is not a release pass.

From Core, check the pinned source objects and all review records:

```sh
python3 tests/check_c312_sync.py --source-repository /path/to/pinned-c-core
python3 -m unittest discover -s tests -p test_c312_sync.py -v
```

The CIU platform companion must also pass. From the platform root:

```sh
python3 tools/toolchain/rust/check-c312-sync.py \
  --c-platform-repository /path/to/pinned-c-platform \
  --c-core-repository /path/to/pinned-c-core
```

Normal CI uses `--structure-only` while the audit is in progress; its output
explicitly says **NOT release acceptance**. Release-tag CI runs the default
gate against separate checkouts of the exact C pins. No checker fetches moving
refs or reads/compiles `reference/legacy-c`. Physical readiness and both product
resource gates remain necessary even after source synchronization passes.

To advance a source pin in a reviewed synchronization change, edit the full
`from`/`to` commits, regenerate the inventory with `--write-inventory` and
`--source-repository`, and review its new SHA256 in the manifest. Update the
expected commit count deliberately. Then inspect each new/changed hunk, update
behavior mappings, rerun applicable regressions and archive their evidence.
Never refresh target/evidence fingerprints merely to silence a stale-record
failure. Source equality evidence is explicitly weaker than execution evidence;
schema and TinyCBOR probes do not execute C transport state machines.

USB lifecycle follow-up adds41 explicitly reviewed units in seven parent/file
diffs. E49 verifies unchanged configuration preserves HALT/auth/RX/output; E50
uses actual reset/reconfiguration plus production main-loop service. E51 routes
empty native C0 to6D00 while generic APDU C0 stays6986. The33-case suite has
equal output. Direct OUT injection does not prove class callback readiness or
IRQ interruption of deferred service. See
[lifecycle comparison](../../tests/fixtures/c312-usb-lifecycle/README.md).


Readiness follow-up adds12 reviewed units in four class-send parent/file diffs.
E52 drives real C class callbacks before service; Rust gates data RX/TX until
an unchanged generation is serviced and rearms OUT once. Unit tests reject
stale acknowledgement after reset. E53 adds four unresolved L8 pending-native
error cases and one equal malformed-envelope case. No actual Provider IRQ
interruption, WebUSB-before-service, withheld-IN or physical acceptance follows.
See [readiness comparison](../../tests/fixtures/c312-usb-readiness/README.md).

WebUSB readiness follow-up adds E54: command SETUP stalls before lifecycle
cleanup, while fresh idle status/configuration and post-cleanup recovery agree
with C. Eight cases/126 events have equal output. Two device-session acquisition
guard hunks are reviewed separately from surrounding CAS/reservation code.
Retained pre-reset WebUSB states, actual Provider IRQ interruption and physical
acceptance remain open. See
[WebUSB readiness comparison](../../tests/fixtures/c312-webusb-readiness/README.md).

E55 adds14 retained-WebUSB cases/605 events with equal output, extending E54.
Global class initialization now preserves nonexecuting status until serialized
cleanup while denying command/response access; executing calls cancel immediately.
Two context-clear/init source hunks are reviewed. Earlier proof snapshots retain
the inputs of their own checkpoints; current source fingerprints are in the new
proof and manifest. No whole-file or arbitrary IRQ acceptance is inferred. See
[retained-state comparison](../../tests/fixtures/c312-webusb-retained/README.md).

The cleanup IRQ checkpoint maps22 additional session/context units and adds
explicit L1 ownership/yield tracking. The real Rust Core Memory capability
sweeps200 lifecycle interrupts across all reached erasure calls in three
retained states. These are separate architectural tests, not new C/Rust wire
cases or arbitrary IRQ/physical acceptance. See the latest progress record.

The CTAP parser checkpoint adds87 reviewed units and explicit C1/C2 records.
445 actual C parser vectors compare every Rust fragment split; C-only reader
fault/cancellation runs and independently verified full-RP responses have
separate scopes. Source cancellation integration and broader canonical review
remain open. See the parser fixture and current progress record.

The NFC source checkpoint leaves source-review counts unchanged and fixes a
reproduced HALT-during-cleanup dispatch bug.41 Rust production-source fault
schedules now cover read errors, HALT/deselect around reads and erasure/release;
source.close is fallible before applet execution. Generic Runtime coverage
blocks publication on failed close. These architectural tests remain separate
from C parser callbacks, portable wire totals and physical acceptance. NFCC
currently overflows Flash by5784 bytes, with no layout/feature workaround.


C3/T16/E56 adds118 explicit source reviews and23 paired largeBlobs cases.
Source aliases/cleanup, exact file-read success, shared prefix/file streaming
and the final response-stream rename deltas are individually mapped. The
250-byte cap is executed for GetInfo/Blob/generated Stream; other response
classes, storage faults and physical/resource acceptance remain open. See
[largeBlobs USB vectors](../../tests/fixtures/c312-large-blob-usb/README.md)
and [NFC vectors](../../tests/fixtures/c312-large-blob-nfc/README.md).
