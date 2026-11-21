# Rust NFC and NDEF integration

The NFCC Rust composition enables NFC, NDEF and all USB interfaces. NFC and USB
are mutually exclusive boot modes. Physical RF, controller timing and complete
NFC stack validation remain open.

`runtime::nfc` owns ISO-DEP block numbers, bounded command delivery, chaining,
duplicate suppression and at most two packet retransmissions. The facade leases
the existing CCID byte allocation after quiescing USB. It enters the shared Core
as owner 4; there is no NFC-private applet or crypto workspace. Request storage
uses the shared 261-byte buffer plus a 27-byte tail for inline envelopes; selected
standalone FIDO bodies above 279 bytes use transient PKE staging, up to 1296 bytes.
Each FIDO extended command's Le controls continuous response aggregation. Core
GET RESPONSE owns the actual response cursor. The facade removes intermediate
61xx trailers only in this compatibility mode.

Inline envelope length is checked with the shared ISO decoder layout before
applet dispatch. Malformed requests close FIDO input/output while preserving
unrelated applet write cursors and grants. They cannot trigger NDEF/OpenPGP
command abort merely because their header resembles an applet command.

## ISO-DEP frames and FIFO ownership

The FM11NT082C FIFO holds 32 bytes. Products with FSC above 32 bytes enable
the FIFO watermark interrupt. RX drains 24 bytes at each watermark and uses
the FIFO count at RX_DONE. For co-latched RX_DONE and watermark flags one
counted drain handles both. The frontend checks CRC, parity and frame format.
Hardware errors, a new activation or a reset revoke partial transfers.
FIFO-sized profiles can read the complete frame at RX_DONE.

Keep the zero-initialized `[u8; FSC]` separate from `Io` state. Initialize
the static state with `Io::new(0, None)` and bind the exclusive backing
reference at startup with `Io::new(now, Some(frame))` under the IRQ lock.
Products with asynchronous polling supply their policy in
`Io<'static, PollingPolicy, FSC>`.

CanoKey checks the generation and calls `take_frame()` under the IRQ lock.
The returned `ReceivedFrame` owns the only reference to the frame until
`return_frame()`. IRQs continue to observe field loss and drain any new
frame, including its tail if the loan ends midway through a drain. Link
decoding and request staging run outside the lock. The main loop returns
the loan under the IRQ lock before acting on its event. A changed generation
suppresses the event and the next poll resets the old Link and request lease.
Callers with their own frame buffer can use `take()` to copy the mailbox.

TX stages the encoded I-block in the IRQ-owned frame buffer and starts with
up to 32 bytes. When 8 bytes remain, each refill writes up to 24 bytes.
The facade releases the IRQ lock after each bus operation or bounded sequence
of operations. TX_DONE confirms delivery and lets the main loop advance its
cursor. A premature TX_DONE, FIFO over/underflow or bus error cancels the
transfer. The masked FIFO_EMPTY bit may still be latched from before TX.
Only the FIFO over/underflow bit reports a FIFO error. The main loop retains
PCB and INF length for exact retransmission from the existing APDU response
window. ACK, WTX, deselect and asynchronous polling replies use the small
inline packet.

The APDU window can already contain an accepted request prefix, bytes still
needed for retransmission, or data owned by an applet while the next RX
frame is unvalidated. Reusing it for FIFO fragments would overwrite live
data before CRC and block-number checks. TX uses the same separate frame
backing as RX. A direct TX read lease on the APDU reply would still require
the RX allocation. The current contiguous wire representation requires
FSC bytes for RX including PCB and CRC, and at most FSC minus two bytes
for TX because hardware appends the CRC.

In Level-4 mode the frontend handles RATS/ATS and PPS and delivers the
subsequent frames via FIFO. The first complete data frame latches FSDI from
the high nibble of `0xFFF6` for the current generation. Valid codes 0 through 8
give FSD 16 through 256 bytes. Reserved codes use the minimum 16 bytes.
An I-block, including PCB and hardware-generated CRC, fits within the
smaller of reader FSD and product TX capacity. Watermarks, chaining and
retries preserve the generation.

The IRQ runtime schedules WTX at 150 ms and recovers dirty links after
200 ms. A power-on, new activation, HALT or forced recovery revokes the old
turn. Loss during execution cancels the command when observed, with Core
cleanup after its call returns. An outstanding WTX echo retains the turn
even if Core has finished. An idle clean link retains authorization.

## ATS provisioning

`runtime::nfc_provision` owns EEPROM configuration, ATS, ATQA/SAK and identity CRC.
It compares before programming, waits for each write and verifies readback.
It always releases chip select. The boot entrypoint runs before GPIO IRQs
are enabled. FM11NT082C v1.2 Figure 3-2 and Table 4-1 place TL/T0 at
`0x03B0/0x03B1` and TA1/TB1/TC1 at `0x03B4..0x03B6`. Provisioning leaves
`0x03B2` (VOUT) and `0x03B3` (I2C address `0x57`) intact.

CanoKey NFCC advertises FSC=256 bytes in ATS `05 78 00 94 00`.
TB1 specifies FWI=9 and SFGI=4 (about 4.8 ms after ATS).
On an already provisioned device the first boot of a firmware with a
different FSCI or SFGI writes and verifies the corresponding ATS fields
when they differ.
The FM11NT loads EEPROM on power-up. A new ATS can therefore be relied
upon after the frontend loses power, restarts, and answers a fresh RATS.
A CIU-only reset while the frontend remains powered does not guarantee
reload. On cold RF startup the frontend can advertise ATS before the MCU
arms FIFO service, including on later boots after EEPROM has been updated.

## NDEF and contactless applet policy

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

- `tools/hil/test_rust_nfc.py`: production raw bus adapter.
- FFI host tests `--lib nfc`: fragmentation, retransmission, FIDO aggregation,
  WTX and reset with mocked Core and registers.
- Transport-runtime `--test nfc_fifo`: bounded FIFO, co-latched flags, reader
  limits, errors, and 256-byte RX/TX and retransmission.
- Rust `--test nfc`: wire, lifecycle, IRQ register and provisioning failure tests.
- Rust `--test ndef`: file policy and actual Core/registry frame routing.
- Combined host `core-behavior`: ADMIN NDEF authorization and read-only/reset APDUs.
- `cmake --preset nfcc` and `cmake --build --preset build-nfcc`:
  real big-endian target compilation and full-feature capacity check.

CIU's full product passes native ownership, capacity and offline boot/recovery
gates. NFCC physical reader/RF compatibility, instrumented I2C timing, deliberate
MPU fault/recovery checks and board-specific stack evidence remain scoped by
the platform's `docs/current-status.md`.

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
