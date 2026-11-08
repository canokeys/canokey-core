# WebUSB admission before lifecycle cleanup

Eight literal cases execute126 events through pinned C and production Rust.
Both deconfigure/configure and bus-reset/address/configure withhold main-loop
service before attempting command SETUP, response fetch, status and
GET_CONFIGURATION. Command SETUP must stall until cleanup completes; status
returns idle and GET_CONFIGURATION returns1 during that interval. A fresh
response fetch stalls because no response exists. Every case then runs cleanup
and an actual Admin SELECT/response transfer to verify recovery.

The before.json observations record two command-admission differences: pinned C
stalls, while Rust incorrectly prepares RX. Other observed responses agree.
Placeholder passed flags in that exploratory capture are not acceptance.
No OUT is sent after rejected SETUP. A new status SETUP supersedes the request
before main-loop cleanup, so the adapter never injects an invalid data stage.

The change passes the USB serviced-generation readiness snapshot into command
admission. It does not gate status or standard EP0 enumeration. The ffi unit
matrix repeats rejection and status/configuration behavior with and without
HID/keyboard and confirms that a WebUSB poll cannot execute a refused command.

These cases start with no previous WebUSB command. They do not establish status
parity for retained pre-reset WebUSB states, arbitrary IRQ interruption of
Provider cleanup, withheld IN, physical USB/RF, or CIU stack/PKE acceptance.
Event-level IN completion remains explicit in the existing adapters.

From Core, reproduce using a separate pinned C checkout and its dependencies:

```sh
python3 tests/support/c312_ccid.py \
  --c-repository /path/to/pinned/core --c-build /path/to/pinned/build-wire \
  --rust-runner ../build/host-core/tests/cargo-usb-sessions/host-test/usb-sessions-rust \
  --vectors tests/fixtures/c312-webusb-readiness/vectors.json \
  --output tests/fixtures/c312-webusb-readiness/report.json
```

CTest c312-webusb-readiness-wire replays the Rust expectations only. E54 adds
WebUSB coverage to E52's actual HID/CCID class-readiness schedules.
