<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust device orchestration and platform boundary

`ffi/device.rs` owns product boot, mode selection, first-boot format permission,
mount/install ordering, self-check sequencing, fault indication, main-loop
transport dispatch and contactless field-loss reset. A readable configuration
with INITIALIZED clear permits formatting; mounted production storage is never
reformatted merely because mounting fails. The platform exposes raw GPIO,
clock, reset, self-check, timer and USB/NFC controller actions.

Live ADMIN configuration changes publish LED and WebUSB landing settings to
disjoint device/USB state. Presence policy restores configured idle LED state
on success, cancellation and timeout. Stored identity is read directly from the
raw configuration page, never through a nested Core or LittleFS session borrow.

`ffi/{ccid_io,hid_io,keyboard_io}.rs` own USB packet mailboxes, reset generations
and endpoint report leases. `ffi/timer.rs` owns the single transport callback
lease. CCID extension bytes and their repeated transmission live in the CCID
IRQ state, not in the shared applet workspace. IRQ callbacks cannot borrow Core,
LittleFS or crypto state. Main-loop handoff is masked through the hardware DCD
lock; polling generation/reset flags uses volatile scalar reads. Reset invalidates
old report generations, and rearming input happens only after the main-loop copy.

The board retains early recovery startup and hardware fault handling required
by the existing 48-vector/ResumeLoader boot contract. Normal firmware does not
use native main-loop, applet, USB protocol or transport scheduling code. The
remaining native storage service is a LittleFS adapter, including raw record
reads/writes/staging and filesystem allocation queries. ADMIN owns storage
attribution, page validation/update, access checks and response encoding.

Validation from the CIU parent repository:

- `tools/hil/test_rust_device.py`: production boot module, ten mode/failure
  scenarios, and timer cancellation/rearming/IRQ-mask semantics.
- `tools/hil/test_rust_ccid.py`: real CCID facade and asynchronous endpoint
  lifecycle, timed extensions, reset and stable in-flight bytes.
- `tools/hil/test_rust_hid.py`: real HID/keyboard facade, resynchronization,
  cancellation, report retry, eject release and reset during submission.
- `tools/hil/test_rust_usb.py`: all eight HID/keyboard/WebUSB feature combinations
  plus a separate hardware DCD register fixture.
- `tools/hil/test_rust_storage.py`: actual LittleFS adapter and persistent files.

These host checks do not establish firmware capacity, physical USB/NFC
interoperability or runtime stack bounds. Full DevKit and NFCC link capacity,
boot-gate completion and hardware validation remain separate acceptance items.

During a CCID or WebUSB core call, cooperative progress services competing HID
initial reports with CHANNEL_BUSY (or INVALID_CHANNEL for an invalid CID).
This path reads only the HID header and never calls Core, transport polling,
reset, or session cleanup. HID CANCEL cannot cancel the unrelated APDU, and
continuations are drained. A pending USB reset is left for normal main-loop
cleanup after the core call returns. Endpoint-owned error packets remain
immutable until IN completion; a second request stays queued while IN is busy.
The `hid-usb` fixture verifies these rules and the USB fixture checks that both
CCID and WebUSB progress dispatch reach the foreign-HID service.

Completed WebUSB responses retain same-owner authorization until timeout or
actual takeover. A queued CCID APDU or a valid-channel HID PING/MSG/CBOR/WINK
may immediately take a completed session with no input chain or unread Core
response. Polling, keyboard activity, HID INIT/CANCEL and continuation reports
do not trigger takeover. EP0 reception/execution/transmission remain exclusive.
The main-loop admission clears WebUSB ownership before resetting Core, so an
old WebUSB timeout cannot revoke the next owner's grant. USB interrupts and
progress callbacks never perform this Core inspection or reset.

`usb-sessions` covers immediate CCID/HID takeover, same-owner grant retention,
partial-response protection, pending EP0 bytes, INIT/CANCEL isolation and stale
timeout cleanup against the real Core. The legacy source-backed-versus-ordinary
response preemption distinction remains a separate compatibility audit item.
