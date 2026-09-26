<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust transport migration contract

Status: Rust USB and WebUSB implementation, 2026-09-26.
CCID, HID execution, keyboard reports and generic USB/HID class policy and WebUSB are Rust-owned. Protocol migration takes
priority over final combined-image size optimization; each replacement still
has to fit its independent device profile and pass stack and correctness gates.

## Completion boundary

The platform-independent core, including transport protocols, will be Rust.
The permitted native dependencies are LittleFS and crypto with narrow adapters.
Board startup, recovery, register access, USB controller drivers and interrupt
mailboxes may remain in C in the platform port. They must not make applet,
authorization, CCID, CTAPHID, keyboard or APDU policy decisions.

Moving existing C protocol files into a platform directory does not meet this
boundary. USB standard requests, EP0 transfer state, configuration/descriptors,
class requests and endpoint response framing are protocol responsibilities too.
The retained C DCD works without the old `USBD_HandleTypeDef`,
`USBD_ClassTypeDef` and protocol callbacks. Compiler support libraries and the
board's boot/recovery code are outside the pure-Rust core requirement.

Existing Rust ownership remains the foundation:

- `protocol`: safe, allocation-free wire codecs and incremental parsers.
- `core/runtime`: transport transactions, applet-session arbitration, input and
  response lifetimes, cancellation and cleanup. Reuse the existing runtime,
  registry and workspace; do not add another APDU engine.
- `ffi`: checked native boundaries, interrupt mailbox access and platform
  adapters. Raw pointers and critical sections do not enter safe core.
- Platform: device operations, bounded buffers actually needed by the controller,
  LittleFS and crypto implementations. No per-applet worst-case buffer.

## Implemented USB boundary

`protocol::usb` decodes SETUP bytes. `runtime::usb` owns descriptor composition,
request validation and control-IN segmentation. `ffi::usb` owns IRQ-local USB
state, endpoint transfer continuations and ZLPs. Its storage is disjoint from
Core and applet transports. All facade entrypoints are serialized by the IRQ
mask. Neither hardware events nor timer callbacks enter the applet runtime.

The hardware-only CIU DCD sends or receives one FIFO packet at a time. It exposes
no USBD_HandleTypeDef, class callbacks or descriptors. Native mailboxes only
copy incoming packets and retain timestamps/epochs; the CCID timer repeats
opaque Rust-prepared bytes. Native USB core, composition and HID class sources
are excluded from Rust builds and the replaced Rust-profile C composition file
has been deleted. The legacy C product still uses its original stack until the
whole-product migration permits removing it.

Configuration descriptors are compared byte-for-byte against captures from all
four previous C HID/keyboard configurations. Host tests cover setup replacement,
status-stage address commit, premature control-IN termination, endpoint halts,
per-interface reset, failed submission, multi-packet transfers, ZLP completion,
suspend/resume, deconfiguration and preservation of new-epoch queued input.
Physical CIU timing and stack acceptance remain pending.

HID execution-time CANCEL, INIT resynchronization, busy errors, keepalive and
lease deadlines now live in `ffi/src/hid_link.rs`. This state is disjoint from
both the borrowed applet engine and `runtime::ctaphid::Transport`: progress must
not reenter either. The CIU adapter publishes an IRQ mailbox and accepts opaque
reports with an epoch check inside a critical section. OUT remains NAKed until
consumption, and IN buffers remain immutable through delayed completion, even
after a software timeout. The control report is distinct from the normal reply
that Rust may be building during a presence wait. Progress copies only the
seven-byte header, avoiding another full HID report on a crypto call's stack.

Keyboard QWERTY encoding and press/release sequencing now live in
`runtime::keyboard` and `ffi/src/keyboard.rs`. A failed send retains the same
report for retry; neither repeated keys nor their releases consume the next
character until completion. Reset generation invalidates pending reports and
cancels the shared output job after competing core ownership has ended.
`core/tests/support/transport_link.rs` compiles these production facades with
fake asynchronous hardware; no test-only copy of either state machine exists.

This stage preserves the existing Rust profile's QWERTY behavior. Legacy custom
keyboard-map configuration and eject compatibility still need an explicit
whole-product audit, as do physical typing, cancellation latency and stack
measurements. Host tests and independent profile links do not close those gaps.

WebUSB is enabled in Rust DevKit builds. NFC/NDEF are still disabled and remain
missing migration work, not evidence that all supported product interfaces are
Rust. USB-only completion and whole-product completion must be reported separately.

## Platform contract

The operations below specify the target semantics. The CCID subset is implemented
in `interfaces/rust-core/ccid_io.h`; USB packet operations are in `usb_io.h`.
Use fixed-width fields and explicit status values; encode wire integers from
bytes, never by exposing native USB/CCID structs. On CIU USB and CCID lengths are
little-endian; APDU extended lengths and CTAPHID identifiers are big-endian.

| Capability | Required semantics |
|---|---|
| Connection snapshot | Configuration state and monotonically changing generation; reset/disconnect immediately invalidates old submissions even before main-loop cleanup |
| Receive lease | Endpoint, length, receipt tick, generation and stable bytes; hold OUT NAKed until the lease is released; no overwrite while Rust borrows input |
| Receive release | End the borrow before rearming; discard obsolete-generation input; a newly queued event must not be cleared by an earlier empty poll |
| Submit IN | Nonblocking `Accepted(id)`, `Busy` or `Disconnected`; no claim of success if no transfer was queued; serialize competing main-loop/timer submissions |
| IN completion | Identify transfer and generation; an accepted buffer remains immutable until completion or confirmed hardware quiescence |
| Endpoint control | Open/configure, stall/clear, arm receive, submit bytes and apply address at the USB-specified phase; no applet or class interpretation |
| Clock/input | Monotonic wrapping millisecond counter, raw touch samples and LED output; Rust owns gesture and authorization decisions |
| Scratch | Bounded acquire/read/write/wipe/release with explicit failure; no Rust slice aliases hardware PKE RAM |

Tick comparisons use elapsed wrapping subtraction with bounded intervals. A
software timeout cancels logical work, but does not revoke a controller's borrow
of its TX buffer. The Rust USB close path clears the CIU FIFO and then revokes software continuation
while interrupts are masked; the driver rejects work on closed endpoints. `FlushEP`
alone is not evidence that a buffer borrow ended. Completion or confirmed
controller quiescence must discharge that lease.

IRQ code may enter disjoint Rust USB state, publish events and operate controller-owned state. It must not
borrow `Core`, applet state, session scratch, filesystem state or PKE. Main-loop
cleanup closes sources, revokes authorization and releases scratch after reset.
Generation checks also occur at submission under the platform synchronization
boundary, so reset between preparing and submitting a response cannot leak an
old response onto a new connection. Critical sections must restore the prior
interrupt mask; do not assume the caller had interrupts enabled.

### Progress while native crypto blocks

OpenPGP/PIV synchronous crypto can block the main loop for many seconds. Merely
queuing a timer event for the next main-loop poll would break CCID liveness.
Moving the current callback to Rust and reborrowing `Core` would violate Rust's
exclusive borrow and the existing FFI contract.

For the first CCID replacement, Rust prepares the complete ten-byte extension
packet, interval (currently 500 ms), connection generation and transfer identity
before calling crypto. A bounded platform link service may repeat these opaque
bytes while armed. It does not parse CCID or modify the packet. Its buffer is
separate from the final response and remains owned until any accepted IN ends.
Publication/disarm and IN arbitration use a short critical section; the ISR
never waits for IN availability. Reset invalidates the generation immediately.

On completion or failure, disarm before queuing the final response. An extension
already in flight must complete before final-response submission; its completion
must not complete the command. A stalled IN retains its buffer even after the
logical transaction is abandoned. The CIU adapter implements this opaque repetition in `platform/rust-core/ccid_io.c`.
The asynchronous host integration tests exercise the real Rust FFI and this
adapter, including timer/disarm races and delayed endpoint completion.

HID execution progress must similarly use state disjoint from the live applet
borrow. A main-loop progress capability can service reports and return
`Continue`, `Cancel` or `Disconnected` without calling back into `Core` or using
PKE. Native crypto with no progress callbacks remains non-cancellable until it
returns; this limitation must stay explicit until primitives support safe
checkpoints. No IRQ may interrupt a primitive to reuse its scratch.

### USB IRQ ownership and aliasing

EP0 remains responsive during native crypto through `ffi::usb`, not cooperative
calls into Core. USB IRQ and timer/main-loop USB operations take the same IRQ
mask and restore its previous value. `DEVICE`, `CONTROL`, `CONTROL_IN` and `TX`
are separate USB globals; none is part of Core, HID or CCID transport storage.
SETUP policy borrows end before calling packet-reset callbacks. Packet callbacks
publish C mailboxes only; raw DCD operations never synchronously reenter Rust.

A DCD write copies one packet to FIFO before returning, so EP0 does not lend its
control buffer to C across callbacks. USB retains raw pointers only for generic
multi-packet IN transfers. Those source bytes stay immutable until completion or
hardware close. CCID's existing response array is now outside `Transport`, with
no increase in aggregate capacity: polling, timeout and session cleanup can
borrow Transport without invalidating the USB reader's pointer. The response
array is mutably borrowed only for a queued execution or after a reset epoch
has quiesced the endpoint. HID control/final and keyboard reports likewise use
separate buffers whose writers wait for completion or confirmed reset.

A reset closes/flushes endpoints before revoking Rust TX leases and publishing
new mailbox epochs. Main-loop cleanup never clears a packet from a newer epoch.
Native C crypto callbacks cannot reach Core through any USB event path.

## First implementation slice: CCID

`protocol::ccid` implements the ten-byte header and literal response encoding;
`core::runtime::ccid` implements receive/execute/respond lifetimes.
`ffi::ccid` exports the main-loop `CCID_Loop` entrypoint. Stage the work
as reviewable changes, but switch the device profile only when the complete
CCID path, including blocking-crypto progress, works. Do not ship two active
CCID state machines for one endpoint.

Preserve these existing contracts unless a separately tested correction is
documented:

- One slot, ATR and T=1 parameters; PowerOn/PowerOff/GetSlotStatus/XfrBlock and
  Get/Reset/SetParameters behavior. Track unsupported-command failure separately
  from its zero-valued error byte. Preserve validation/error precedence.
- Fragmented ten-byte headers and checked `dwLength` arithmetic. Receive timeout
  is 2000 ms using packet receipt time; a late packet cannot revive expired input.
  A partial header cannot provide reliable slot/sequence for an error reply.
- Short APDU input is at most 261 bytes and response at most 258 bytes, excluding
  the ten-byte CCID header. Standalone extended FIDO accepts up to 1024 CTAP bytes
  plus seven-byte prefix and optional two-byte Le, only in CTAP-enabled profiles.
  ISO APDU chaining and CCID packet assembly remain separate layers.
- Validate selected FIDO applet, envelope and session before acquiring PKE.
  Keep prefix/Le in bounded RAM and stage only the CTAP body. Close the input
  source before presence waits, token verification or crypto. Close exactly once
  on completion, malformed input, timeout, reset and storage-access failure;
  failed scratch wipe/release must not permit reuse.
- Acquire the shared applet session before staging; keep active operations
  exclusive. Preserve the existing two-second idle cross-transport lease and
  ordinary same-owner PIN grants/chains. Slot discovery must not revoke the HID
  owner's authorization. Do not add a second independent lease authority.
- Final response, extension and endpoint completion have distinct identities.
  Reset during execution suppresses the old reply and defers core cleanup until
  no old Rust borrow is live.

Both `interfaces/rust-core/ccid.c` and `interfaces/USB/class/ccid/usbd_ccid.c`
are absent from Rust firmware inputs. The platform packet adapter implements
endpoint I/O, generation checks, mailbox synchronization and opaque transfers.
Rust supplies response bytes, extension bytes and final ZLP policy. Generic
USB and WebUSB policy also use Rust; NFC/NDEF still require migration.

### Tests required for the CCID switch

| Layer | Required evidence |
|---|---|
| Codec | Literal LE/BE vectors, all header splits/truncations, maximal and overflowing lengths, slot/sequence preservation and exact error/status bytes |
| Runtime with fake endpoint/scratch | Commands and error precedence; timeout across tick wrap; PKE acquisition failures and close-once behavior; input closed before execution; HID/CCID lease contention |
| Endpoint/timer integration | Delayed completion, busy submission, exact-packet ZLP, reset during receive/execute/submit, event during empty poll, 500 ms extension during blocked crypto, disarm/final response races and stalled IN buffer retention |
| Existing applet regression | ADMIN/PASS/OATH/OpenPGP/PIV/CTAP host flows and response chaining retain their behavior through the new transport |
| DevKit | Enumeration/PCSC, short and extended FIDO, long RSA operation with time extensions, USB reset and transport contention, measured full-path stack and firmware identity |

`core/tests/ccid.rs` covers runtime and scratch semantics. The CIU parent
`tools/hil/test_rust_ccid.py` links the actual Rust FFI and platform packet adapter
against asynchronous fake USB hardware in `tests/host/rust_ccid_usb.c`.
It covers delayed IN/ZLP, reset generations, timer races and mask restoration.
The HID adapter still has its separate C fixture. Physical raw USB checks live
in `tools/hil/rust_ccid_wire.py`; macOS kernel-driver detachment currently fails
without elevated USB access, so those checks are not yet hardware evidence.

## Subsequent slices and final gates

1. CCID, as above, plus the shared session/progress boundary it needs.
2. Move HID execution-time policy and keyboard report generation into Rust;
   consolidate cross-transport arbitration without expanding the workspace.
3. Replace USB descriptors, class requests and standard EP0/device state, then
   remove the remaining C USB class/core dependency. Retain only the board DCD.
4. Implement WebUSB, NFC protocol handling/WTX and NDEF with the same ownership
   contract. NFC bus/register drivers stay in the platform. Restore NFCC only
   after its feature and capacity gates pass.

For every slice, test isolated and combined host features and applicable device
profiles. Preserve boot recovery's 48-vector/early-ResumeLoader gate, BE8/Thumb-1
ABI, effective crypto optimization flags and the FS layout. Build normal C
DevKit and NFCC after shared core/build changes. Record final-link Flash/static
RAM and measure affected full-path stack; host or link success is not stack HIL.
Existing PIV P-521 attestation stack excess remains an unresolved issue, not a
new transport budget. No final size saving is assumed from changing language.

The final build gate must use resolved source inputs (CMake File API or equivalent)
and link evidence together: reject legacy C applets, dispatch/session code,
`interfaces/rust-core/{ccid,ctaphid,usb}.c` and C USB protocol files in Rust
firmware. A symbol-only gate is insufficient under LTO. Keep a narrow explicit
allowlist for crypto adapters and LittleFS; review platform helpers for hidden
protocol policy. The CCID/HID/USB stage gates now check resolved sources and retained Rust
ownership. `verify-usb.py` additionally inspects the compiler command database,
including transitive native target inputs. The full-stack allowlist remains future work.

The host Rust transport tests must run without C USB libraries; native crypto
and storage integration tests remain separate. Whole-product completion also
requires the enabled interfaces to work together on device and fit the target,
not merely disappear from the build.

## WebUSB control and shared storage

`runtime::usb::webusb` streams BOS, URL and Microsoft OS 2.0 descriptors from
constants. The 178-byte Microsoft descriptor is patched at byte 22 for the
actual WebUSB interface; it does not require a larger EP0 RAM buffer. Interface
order remains HID, WebUSB, CCID, keyboard, omitting disabled optional classes.
The WebUSB interface string remains index 0x12 and bcdUSB becomes 0x0210.

Device discovery uses IN vendor requests `(request=1, value=1, index=2)` for the
URL and `(request=2, value=0, index=7)` for Microsoft OS 2.0. Interface requests
require value zero and the actual interface index: OUT command 0 (at most 261
bytes), IN response 1 (at most the prepared 258 bytes), IN status 2 (one byte).
Malformed directions, recipients, lengths and indices stall EP0. The status
bytes preserve idle FF, receiving 03, processing 01, response-ready 00,
sending 02 and held-session 04. Short reads consume that transport reply;
logical APDU GET RESPONSE chaining remains in the existing Core engine.

`ffi::webusb_link` reserves the channel in IRQ context but does not acquire
Core there. If the first OUT packet arrives while another Core call is live,
only a 16-byte mailbox is filled and the FIFO remains held. Main-loop admission
checks the existing CCID/HID lease state before copying that packet into the
existing CCID response allocation. Rejected admission never resets the foreign
session. CCID/HID entrypoints yield to this reservation; keyboard can finish an
already submitted key release without entering Core. No additional maximum-size
command, response or crypto workspace is allocated.

After admission, the same allocation receives the rest of the command and then
holds the response. `ck_core_exchange(owner=3)` ends its input borrow before
borrowing output, so the exact same pointer can be used for RX and TX. IRQ
status/discovery requests use disjoint EP0 storage while execution borrows the
APDU buffer. During response transmission, competitors cannot reuse that buffer
until actual completion/explicit endpoint quiescence. A software timeout never
ends an in-flight pointer lease. A reset during execution marks the result for
discard and defers Core cleanup until the running borrow has returned.

An idle WebUSB session expires after two seconds, with wrapping tick arithmetic.
Polling status refreshes the held-session deadline. Same-owner commands retain
applet selection, PIN grants and APDU chains; acquiring a free/expired foreign
session resets the previous Core state once. USB reset, deconfiguration and
WebUSB SET_INTERFACE release protocol state without resetting other endpoint
mailboxes. Full physical browser/Windows/CIU timing and stack acceptance still
require a connected device.

Host coverage includes literal discovery fixtures, every short command length,
all descriptor packet boundaries, eight HID/keyboard/WebUSB combinations, the
actual EP0 facade, busy foreign sessions, maximum command reassembly, status
polling during execution, superseded setup, reset during execution, response
truncation, idle expiry and keyboard release while WebUSB holds the session.

Cooperative progress dispatch also lives in Rust. Native services perform only
a one-millisecond hardware delay before asking the active Rust transport whether
execution is still live. WebUSB touch/crypto waits therefore do not depend on a
CCID extension timer, and USB reset cancels them without reentering Core.

### HID ingress and echo correctness coverage

The Rust OUT mailbox holds one report and its receive timestamp until main-loop
consumption rearms the endpoint. It does not execute protocol code in the IRQ.
`hid-core::mailbox_regressions` checks overwrite rejection/rearm, 50 ordered
reports and arrival-time timeout decisions under delayed dispatch. `hid-usb`
checks interrupts during polling and queued cancellation with an IN report
still owned by the controller.

PING uses the available transient staging capacity, capped at the 7609-byte
HID framing limit; it is not subject to the 1024-byte CTAP CBOR limit. MSG retains
its additional nine envelope bytes. Length admission happens before acquisition,
and echo storage is wiped/released after final transmission or interruption.
The full adapter fixture verifies boundaries through its 3072-byte scratch
capacity and rejects capacity+1 without acquiring storage. The platform's
actual capacity remains authoritative; no Flash transport cache is used.
