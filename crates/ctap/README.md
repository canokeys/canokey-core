# canokey-ctap

Allocator-free CTAP mechanisms, independent of Core, FFI, native crypto and
product applications. Firmware uses `no_std` without the `schema` feature.

- `config`, `status`, `request`: standard command/status values and exact
  parameterless command admission. Parameterized command parsing stays with the
  products until its migration.
- `info`: GetInfo encoding over immutable product policy fragments and a bounded
  synchronous sink. Host-only `schema` compiles supplied fragments; it does not
  read product directories.
- `workspace`: exclusive reservations of existing product backing. Drop erases
  unpublished bytes; publish ends the loan without allocating or retaining it.
- `presence`: synchronous time/touch/progress capability and the two product
  gesture mechanisms. Reset policy and transport ownership stay in adapters.
- `session`: non-sensitive continuation binding and wrapping idle timestamps.
  Products own cursor secrets, timeout policy, refresh points and reset.
- `provision`, `settings`: attestation read admission, certificate publication
  latch, and the eight-byte SM2 settings codec. Capabilities address only their
  own material; product ADMIN authority and installation policy stay outside.
- `resident`: borrowed CTG1 member decoding, bounded field encoding, UTF-8
  truncation and RP display. `resident::group` validates CTG1 headers and plans
  member offsets/replacement lengths without IO. `group::update` shares no-op,
  same-length patch, variable replacement and deletion across synchronous
  backend capabilities. Constants express buffered peer reads before a staging
  lease versus closed-append streaming, and all-member versus target-only patch
  validation. Products lend existing scratch and retain capacity, preflight,
  atomic commit/abort, recovery status and scratch erasure policy. Credential
  derivation and enumeration remain with their owners during R06 migration.
- `response`: exact/partial certificate window admission. Product backing and
  source close/erasure remain with their owners. General response cursors and
  segmented reads use `canokey-protocol::response`.

No capability retains a product storage/application/transport borrow across
calls. IRQs publish mailbox state; only the serialized owner enters applet code.
The crate adds no complete RX/TX backing or firmware heap. Products need not
install capabilities they do not support (for example vLEI SM2 or streaming
certificate installation).

Run the portable suites without linking a product:

```sh
cargo test -p canokey-ctap
```

`standalone` covers command admission and `get_info` encodes/decodes GetInfo
using only portable dependencies. Other suites check lifetime/erasure, bounded
reads, publication, time policy and fixed product snapshots. These host tests do
not qualify hardware, native cleanup under Linux sanitizers or resource budgets.
