# Existing WebUSB transactions across lifecycle cleanup

Fourteen literal cases execute605 events through pinned C and production Rust.
Each starts in one of seven states: command SETUP waiting for main-loop
admission, partial RX, response ready, response IN pending, completed Hold,
authenticated Admin Hold, or Hold with a retained finite-Le FIDO source.
Each state runs both deconfigure/configure and bus-reset/address/configure
with serialized lifecycle service withheld.

Before cleanup, three status observations surround rejected response/command
SETUPs. No OUT follows rejection. Ready response and completed Hold retain
status00/04 until service. A new SETUP aborts partial RX or a pending response
IN stage to idle; those statuses areff. After POLL, all states reportff, an
old generic GET RESPONSE returns6986, fresh Admin SELECT succeeds and empty
VERIFY reports63c3 rather than retaining authentication. Only the PIN-Hold
cases verify the known default PIN beforehand; no guesses or physical device
are involved.

The before.json exploratory observations show eight mismatched cases, with
24 status differences: Rust reset toff early while C retained00/04. Placeholder
passed flags are not acceptance. The fix defers nonexecuting WebUSB state reset
to serialized lifecycle service and gates both command and response admission.
An interrupted executing call is still cancelled immediately; its workspace
cannot be reused before unwinding. Local EP0 failure/reset behavior stays
separate. The ffi unit matrix checks ready/Hold across both lifecycle forms
with and without HID/keyboard, refuses old transfers, and prevents execution
of a refused command. Existing execution-reset units cover cancellation with
policy substitutes; this dual suite does not inject executing IRQs.

The adapters model explicit EP0 IN completions, including a response SETUP
superseded before its IN completes. HID/bulk IN still drain per event. These
are serialized virtual schedules, not physical USB, arbitrary Provider cleanup
interruption, simultaneous hardware failures or CIU call-path stack/PKE proof.

From Core, reproduce with a separate pinned C checkout and dependencies:

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned/core --c-build /path/to/pinned/build-wire \
  --rust-runner ../build/host-core/tests/cargo-usb-sessions/host-test/usb-sessions-rust \
  --vectors tests/fixtures/c312-webusb-retained/vectors.json \
  --output tests/fixtures/c312-webusb-retained/report.json
```

CTest c312-webusb-retained-wire replays the Rust expectations only. E55 extends
E54's fresh-product readiness coverage with existing transaction state.
