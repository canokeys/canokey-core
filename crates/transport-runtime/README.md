# Shared transport runtime

This `no_std` crate forbids unsafe code and depends only on `canokey-protocol`.
It owns mechanisms used by product facades, without an application registry,
native bindings, persistent storage or heap allocation.

- `nfc` provides ISO-DEP Link, execution/WTX and recovery state.
- `nfc_io::Io<P>` owns the IRQ frame mailbox, RF turn and recovery. `Chip` is
  synchronous borrowed IO; `Polling` is a static, pure product capability.
  `NoPolling` has no state. A polling completion cannot enter an application.
- `nfc_provision` configures and verifies the NFC EEPROM through borrowed IO.
- `usb::Device<P, BUFFER>` validates standard control and HID requests.
  `Profile` supplies identity, bounded idle state, reset/reconfiguration policy
  and optional discovery handles. `Configuration` supplies installed interfaces,
  endpoints and HID reports. Both are trusted static product capabilities:
  descriptors must fit the caller's control buffer, and HID idle slots must
  address the profile's own idle state. No capability borrows an application,
  session, hardware controller or shared APDU workspace.
- `usb::ControlIn` tracks control-IN ranges and short-transfer ZLP termination.
  The facade advances it for the initial packet and after each acknowledged
  packet; asynchronous hardware retains only facade-owned packet storage.

USB buffer capacity is a const generic, so a product with a 128-byte control
buffer does not allocate the other product's 160-byte capacity. An uninhabited
discovery handle disables descriptor streaming in a product's type. Fixed CTAP
HID/report and language descriptors, and bounded UTF-16LE string encoding, are
shared. Product device/configuration descriptors, interface composition, BOS
content, endpoint IO and application/session reset orchestration remain outside
this crate. Repeating SET_CONFIGURATION can either acknowledge or request the
product reset action, selected statically by the profile.

Run `cargo test -p canokey-transport-runtime` and the owning products' transport
and USB composition suites. A host test does not qualify physical USB/RF IO or
prove an embedded stack budget; the linked product ELF needs its own review.

`ccid::Transport<P, I>` shares envelope draining, dispatch, reply and endpoint
completion state. `Buffered` retains one short APDU for CanoKey; receive uses a
no-op backend and cannot enter the application. `Streaming` retains only begin
and timeout metadata and feeds the product's existing application owner.
Product `Policy` preserves validation precedence, ATR/T=1 bytes, parameter
commands and success sentinels. The facade owns reply storage and its in-flight
lease. `Polling<P>` handles asynchronous status/cancel with only a five-byte
prefix and cannot borrow a backend. Header progress and remaining u32 payload
are separate counters, so UINT32_MAX payloads cannot overflow header addition.
Neither ingress strategy admits extended APDUs; NFC admission is independent.


`ctaphid::Session<P>` owns channel allocation, framing, receipt timestamps,
sequence checks, response splitting and final endpoint completion. Static
profiles retain channel registration/wrap, CANCEL and timeout boundary policy.
`Backend` borrows the product input owner synchronously; `Response` and
`Completion` are separate capabilities so transmit and final acknowledgement
cannot acquire an application or request parser. CanoKey keeps its existing
192-byte inline/PKE staging and native continuation owner; vLEI borrows its
existing request/response arrays. No payload storage is allocated by Session.

`ctaphid::Execution<P>` holds execution CID/generation, cancellation,
abandonment and keepalive timestamps. It classifies only a borrowed report or
peeked header and cannot call applications or IO. INIT retention and CANCEL
latching are shared; a static policy preserves malformed-INIT error selection.
CanoKey records keepalive publication after synchronous send; vLEI uses the
existing pre-submit timestamp. Endpoint busy/timeout, mailbox consumption and
main-loop cleanup remain in product facades. Ending execution invalidates its
CID while retaining abandonment until suppressed output is released.
