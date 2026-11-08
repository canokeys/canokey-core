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
