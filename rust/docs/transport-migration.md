<!-- SPDX-License-Identifier: Apache-2.0 -->
# Rust transport migration contract

Status: Rust HID execution and keyboard migration, 2026-09-25.
CCID and HID execution policy are Rust-owned; generic USB and HID class handling still use C. Protocol migration takes
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
The retained C DCD must eventually work without the old `USBD_HandleTypeDef`,
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

## Remaining native protocol responsibilities

Paths in this table are relative to `canokey-core`. The CIU-specific source
inventory is maintained in the parent port at
`docs/rust-transport-inventory.md`.

| Current source | Responsibility to replace | Rust destination |
|---|---|---|
| `interfaces/USB/class/ctaphid/usbd_ctaphid.c` | HID class requests/descriptors and report transfer state | Rust USB HID class |
| `interfaces/USB/class/kbdhid/usbd_kbdhid.c` | Keyboard HID requests/descriptors and report state | Rust keyboard HID class |
| `interfaces/rust-core/usb.c` | Composite descriptors, interface/endpoint routing and class initialization | Rust USB device composition |
| `interfaces/USB/device/usb_device.c` | Device/class registration and lifecycle | Rust USB device composition plus platform startup call |
| `interfaces/USB/core/src/usbd_core.c`, `usbd_ctlreq.c`, `usbd_ioreq.c` | USB standard requests, setup decoding, device and EP0 control-transfer state | Rust USB device/control layer |

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

WebUSB and NFC/NDEF are disabled in the current Rust DevKit build. They are
missing migration work, not evidence that all supported product interfaces are
Rust. USB-only completion and whole-product completion must be reported separately.

## Platform contract

The operations below specify the target semantics. The CCID subset is implemented
in `interfaces/rust-core/ccid_io.h`; generic USB/HID migration remains pending.
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
of its TX buffer. The Rust-profile CIU `CloseEP` clears the FIFO and software continuation while
interrupts are masked; the driver rejects work on closed endpoints. `FlushEP`
alone is not evidence that a buffer borrow ended. Completion or confirmed
controller quiescence must discharge that lease.

IRQ code may publish events and operate controller-owned state. It must not
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

EP0 must also remain responsive during long crypto. Before removing the old USB
control layer, supply either proven bounded cooperative service or a separately
owned Rust USB link service that cannot reach `Core`. The latter requires its
own documented IRQ ownership/aliasing proof; it is not permission to call today's
main-loop FFI entrypoints from interrupts.

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
Rust supplies response bytes, extension bytes and final ZLP policy. Generic C
USB still routes class callbacks; this is not a fully Rust protocol stack.

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
protocol policy. The CCID subset is enforced now by the CIU `verify-ccid.py` gate: resolved
sources and linker inputs exclude both legacy CCID files and `CCID_Loop` must
come from the Rust archive. The full-stack allowlist remains future work.

The host Rust transport tests must run without C USB libraries; native crypto
and storage integration tests remain separate. Whole-product completion also
requires the enabled interfaces to work together on device and fit the target,
not merely disappear from the build.
