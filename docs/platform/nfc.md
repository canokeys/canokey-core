# Rust NFC and NDEF integration

The NFCC Rust composition enables NFC, NDEF and all USB interfaces. NFC and USB
are mutually exclusive boot modes. This integration is still under validation:
the full NFCC image does not fit Flash, and no physical NFC reader or runtime
stack acceptance has
been performed. Do not treat host tests as a release qualification.

`runtime::nfc` owns ISO-DEP block numbers, 261-byte command bounds, chaining,
duplicate suppression and at most two packet retransmissions. The facade leases
the existing CCID byte allocation after quiescing USB. It enters the shared Core
as owner 4; there is no NFC-private applet or crypto workspace. Case-3 FIDO SELECT
enables continuous response aggregation for subsequent extended commands. Core
GET RESPONSE owns the actual response cursor; intermediate 61xx trailers are
removed only in this compatibility mode.

`runtime::nfc_io` owns the IRQ mailbox, 150-ms WTX schedule and 200-ms dirty-link
recovery. The main-loop facade masks interrupts only around this disjoint state.
No IRQ borrows Core, storage or the shared APDU bytes. Field reset cancels the
running command, and Core cleanup occurs after its call returns. A pending WTX
echo retains the RF turn even if Core has already finished. Clean idle links keep
their applet authorization. Reset, deselect or forced recovery clear it.

`runtime::nfc_provision` owns EEPROM configuration, ATS, ATQA/SAK and identity CRC.
It compares before programming, delays for EEPROM writes and verifies readback;
every error releases chip select. Its boot entrypoint runs before GPIO IRQs are
enabled. The platform adapter supplies only raw register/bus, chip-select, delay,
IRQ mask and timer actions.

NDEF uses the existing applet-state union and response cursor. Complete UPDATE
BINARY frames commit through storage; truncated frames do not publish data. The
1024-byte file is streamed. Records 184/185 map to legacy `E103`/`NDEF` paths on
CIU, retaining existing contents and permissions. Other Rust record mappings do
not change. ADMIN `07` resets NDEF and `08` sets read-only mode (P1=0/1); both
require ADMIN authentication. Read-only failure reloads persisted permissions.
NDEF read/write commands enforce the CC access bytes.

Contactless ordinary presence waits and U2F polling check transport liveness
without polling touch hardware. ADMIN factory reset is rejected in NFC mode with
6985; five-touch reset remains available only over a contact interface.

Validation entrypoints:

- `tools/hil/test_rust_nfc.py`: production raw bus adapter and NFC FFI with mocked
  Core/registers; fragmentation, retransmission, FIDO aggregation, WTX and reset.
- Rust `--test nfc`: wire, lifecycle, IRQ register and provisioning failure tests.
- Rust `--test ndef`: file policy and actual Core/registry frame routing.
- Combined host `core-normal`: ADMIN NDEF authorization and read-only/reset APDUs.
- `cmake --preset nfcc-rust-all` and `cmake --build --preset build-nfcc-rust-all`:
  real big-endian target compilation and full-feature capacity check.

Still open: LED/WebUSB landing consumers of the common configuration flags,
complete native ownership gates, capacity reduction,
boot/recovery gate completion, physical reader compatibility and stack paint.

The native-endian configuration-page layout is preserved by `runtime::config`.
NFC enable/disable (`14`, P1=0 read or P1=1 authenticated write, P2=0/1), ADMIN
configuration (`40`) and six-byte configuration readback (`42`, Le>=6) share that
policy. OpenPGP/PIV use independent NFC/contact bits; WebAuthn guards APDU and
CTAPHID CBOR/MSG; NDEF selection and PASS output honor their flags. Factory reset
restores ADMIN flags while retaining the NFC bit and unrelated identity/keymap/
TLV fields. The page buffer is aligned, local to configuration calls and never
live across crypto. No additional static configuration page is allocated.

Erased pages use legacy defaults without programming Flash during a read.
Malformed non-erased pages and read errors deny restricted features; this
intentionally avoids enabling default permissions after a torn write. ADMIN
remains selectable so an authenticated update can repair metadata. Every update
preserves a valid page's unrelated bytes and re-reads the loader-owned word
before the aligned full-page write. Write failure is uncertain; subsequent reads
reload and validate actual storage rather than relying on a success cache.
