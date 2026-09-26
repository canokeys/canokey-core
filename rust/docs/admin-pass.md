<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADMIN + PASS implementation checkpoint

This checkpoint establishes the independent core's first applet composition.
Published protocol behavior is the migration contract; C behavior is a
reference where the protocol is silent, not a requirement to accept malformed
commands. The user explicitly
confirmed retaining default ADMIN PIN `123456` and three retries.

## Implemented protocol

ADMIN AID is `F0 00 00 00 00`. All implemented commands below use CLA 00. P2 is zero; command bodies are bounded at 64 bytes.
SELECT and GET RESPONSE belong to the runtime. Reset or applet switch revokes grants; same-ADMIN selection preserves them.

| INS | P1 | Body | Preconditions and result |
| --- | --- | --- | --- |
| 20 | 0 | Empty | 9000 if authorized, otherwise 63Cx; does not revoke a grant |
| 20 | 0 | PIN, 6–64 bytes | Verify, restore retry count durably, grant this session |
| 21 | 0 | New PIN, 6–64 bytes | ADMIN grant; replace PIN/reset retries, revoke grant |
| 43 | 0 | Empty | ADMIN grant; return two slot descriptions without secrets |
| 44 | 1 or 2 | `00`, `02 length password enter`, or `03 14 key20` | ADMIN grant; atomically replace slot configuration |
| 13 | 0 | Empty | ADMIN grant; atomically clear both PASS slots |
| 50 | 0 | ASCII `RESET` | Locked PIN and strong presence; reset enabled applets and ADMIN PIN |

Verification preserves C behavior: compare PIN bytes and length, persist a
retry decrement on mismatch, restore retries after a match if necessary, and
never grant authorization after a storage error. Wrong PIN returns 63Cx, with
6983 when blocked.
READ PASS uses GET RESPONSE when an explicit Le limits the reply. A touch of
at least 30 ms selects slot 1; a touch of
at least 500 ms selects slot 2. The output job lives in Rust and handles C HID
backpressure one character at a time. C owns ASCII-to-HID mapping and press /
release sequencing, and never retains the whole password or calls C PASS.

## Records and backend

All byte encodings are independent of C layout and CPU endianness:

- `01`: version, PIN length, retries and limit, followed by the actual PIN
  bytes (10 bytes for the default PIN). No hashing, salt or KDF is added.
- `00`: two length-delimited version-2 PASS records, each containing its
  four-byte header and actual payload. OATH bindings add a four-byte stable ID.
  Two disabled slots occupy eight bytes. No previous-format decoder is retained.
- `t`: atomic-replacement temporary file; close then rename. The current
  record is never updated in place. Failed mutations invalidate cached state;
  uncertain storage errors disable backend access until reboot.

Only NotFound creates the default PIN. Invalid records and I/O errors fail
closed. This preserves C's missing-record initialization policy but does not
detect malicious deletion with raw Flash access. Provision fresh storage;
compatibility with previous C or Rust layouts is not supported.
The PASS service keeps a missing record in RAM until the first successful
configuration write; merely opening the applet does not create a persistent
record.
LittleFS mount failure never formats. The file cache is aligned to four bytes
because CIU page programming reads words, including non-inline file payloads.

Firmware startup and recovery remain the original C implementation.

## Remaining compatibility work

This is not yet the full C ADMIN command set. Device configuration/enable flags,
version/serial/usage reporting, custom keyboard maps
and vendor hooks still need their typed services and normal functional coverage.
They currently return INS_NOT_SUPPORTED. Commands managing CTAP/PIV/OpenPGP/
NDEF will arrive only with those applets; none are linked implicitly.
The OATH profile additionally enables authenticated ADMIN INS 05 RESET OATH.

HMAC computation is covered through the typed service and C ABI. The optional
OATH profile now also provides the existing YubiKey HMAC USB binding.
Keyboard HID enumerates, while automatic tests validate Rust output without
injecting keystrokes into the user's desktop. Physical-touch/end-to-end typing
needs a deliberately focused capture target. No exhaustive or boundary suite
is part of this checkpoint.

## Protocol-based review (2026-09-22)

Normative source for implemented ADMIN commands:
[Admin Applet protocol](https://docs.canokeys.org/development/protocols/admin/),
retrieved 2026-09-22. Published wire requirements take precedence over accidental
permissiveness in the C implementation. Missing commands remain explicitly
unsupported; this is not a claim of full ADMIN protocol coverage.

- ADMIN accepts CLA 00 only in this profile. The documented CLA 10 exception
  belongs to Write FIDO Certificate (02), which is not enabled yet. Generic
  chaining remains a common protocol capability, not an ADMIN extension.
- Unknown/disabled instructions return 6D00. Implemented protected commands
  require ADMIN authentication; their P1/P2 and length constraints are checked
  strictly. C's unknown-command 6982 precedence is not reproduced.
- Same-ADMIN SELECT preserves the grant. Unknown AID or invalid SELECT P2 does
  not discard the selected applet. Switching applets revokes ADMIN grants.
  Applet-specific SELECT authentication remains the applet's responsibility.
- Missing Le means the bounded response is returned immediately; explicit
  short Le uses GET RESPONSE. This covers Read Pass Config, whose published
  description does not require an Le field. Future commands with documented
  minimum Le requirements must enforce those in their own adapters.
- Backend failures map to 6900; semantic validation errors retain their specific
  protocol status. Response storage is sized for two maximum OATH descriptions
  (134 bytes), not the former four-byte static/HMAC-only result.
- Factory Reset (50): P1/P2=0, exactly ASCII RESET, locked PIN required. USB is
  the only enabled transport. Rust prompts five fresh short press/release
  gestures, each within a two-second blinking window, separated by two seconds.
  C supplies only raw LED/input/time and CCID keepalive. Failure returns 6982.
  PASS and enabled OATH data are cleared before the PIN is restored to 123456
  with three retries; identity/SN and legacy C files are untouched. The PIN is
  committed last so a partial failure remains locked and can be retried after
  remount. This is not an atomic transaction across all applet records.

### Deliberate strictness and output policy

Static with-enter flags are restricted to 0/1. Extra command bytes and reserved
P1/P2 values are rejected; legacy C acceptance is not a requirement. Password
storage is length-delimited; NUL has no HID mapping and is skipped rather than
terminating the rest of the output. The undocumented FF EE FF EE eject APDU is
not enabled. PASS HMAC type 03 and its OATH-selected compatibility route remain
an explicitly supported extension; the public ADMIN page does not list it.

Keyboard gestures require at least 30 ms; 500 ms selects the long slot. Contacts
in the first 1.5 seconds after power-on are ignored and must be released before
arming. While an APDU command chain or response is pending, a PASS gesture is
discarded and requires a new touch. While keyboard output is active (including
its final report release), new ordinary APDUs return 6985. Link reset cancels
output and authentication. Busy requests do not queue secret text. The future
multi-transport scheduler/Busy indicator is not implemented by this CCID-only
profile; serialization and these explicit lease checks cover the current paths.

Normal host validation includes same-AID reselection, missing-Le discovery,
static output, and the complete locked-PIN -> five-touch -> restored-PIN flow.
The host supplies raw input timing, not a production presence-bypass command.
Hardware factory-reset validation requires a separate user-assisted five-touch
run; do not infer it from the prior single-touch OATH test.

### Device configuration and keyboard layout migration

Rust retains the native-endian 512-byte platform configuration format, including
CRC, loader-word exclusion and write-once serial at bytes 16..20. ADMIN `30 00 00`
requires authorization and four serial bytes; `32 00 00` reads four bytes with
Le >= 4. Missing or invalid identity reads as zeros; a second serial write returns
6985. Config updates preserve serial, keyboard and algorithm fields.

Authenticated ADMIN `45 00 <layout>` writes exactly 256 bytes, one
`{modifier, usage}` pair per ASCII value. It accepts a short-APDU command chain,
using the shared session workspace until the final command validates and commits
one configuration page. `46 00 00` (Le >= 1) reads the layout ID; `46 00 01`
(Le >= 256) reads the table. Both require an empty command body and return 6A88
when no layout is installed. `47 00 00`, with an empty body, clears the layout.
All three commands require ADMIN authorization. A configured usage of zero
suppresses that character; clearing the table restores the built-in US layout.
The loader word, serial and optional algorithm TLVs survive layout updates.

ADMIN command and response data borrow the existing session workspace. They do
not add a keyboard-table cache or enlarge the transport APDU buffer. Unit tests
cover literal legacy page offsets and zero-usage behavior; the combined native
fixture verifies APDU chaining, persistence, grant revocation and clear/readback.

`31 <kind> 00` exposes firmware version (kind 0), product name (1) or core
revision (2); `32 01 00` exposes the 13-byte chip ID. These read-only commands
need no authorization and accept no data. Responses truncate to Le and do not
create pending GET RESPONSE data. The board supplies only raw metadata and chip
bytes; Rust validates command shape and bounds the response.

Authenticated vendor command `FF FF <mode>` requires the exact 15-byte literal
`D3549Fa2dcb$23n`. Mode 0 writes the board's loader handoff word while preserving
all remaining configuration bytes, including corrupt metadata. Mode 1 rebuilds
an erased configuration page containing only that handoff word. Neither mode
resets the device. Other parameters or payloads return 6A86; missing recovery
capability and storage failures return 6900. The explicit mode-1 operation loses
serial, keyboard and other configuration metadata, matching the CIU vendor
command. Unit tests cover raw-page preservation, erase semantics and I/O errors;
host APDU tests cover authentication and parameter rejection.

The legacy special APDU `FF EE FF EE` queues keyboard consumer-control Eject
when PASS is enabled, regardless of the selected applet. It requires no ADMIN
PIN and retains legacy acceptance of command data. The command is only queued
after the complete frame validates. It replaces queued text; the keyboard
transport finishes any prior key release before sending Eject (report ID 2,
usage B8), then sends report ID 2 with a zero usage. USB epoch/reset discards
pending output. An explicit eject does not require touch or wait for the startup
touch ignore window; subsequent gestures still use the normal timing policy.
The HID facade fixture tests a failed Eject submission, byte-stable retry,
release while WebUSB owns the session, and USB-reset cleanup.

Public ADMIN `41 00 00` (Le >= 2) returns `{used_kib,total_kib}`, retaining
integer truncation and the original byte-sized fields. `41 01 00` (Le >= 48)
returns eight six-byte records: `{applet_id,flags,logical_bytes_be32}` for ADMIN,
OpenPGP, PIV, OATH, CTAP, NDEF, PASS, then system (ID 0). A missing known record
sets flag bit 0 and contributes zero; storage errors return 6900. P2 must be zero.

Attribution follows the Rust durable record namespace, including optional or
currently disabled applet records. Security metadata stored inside a Rust record
is included in that record's payload size. Filesystem metadata, old/unrecognized
files and temporary files contribute to the nonnegative system remainder.
LittleFS supplies allocated and total bytes; all grouping and wire encoding is
Rust. The operation is read-only and uses the existing response workspace.

### Deferred keyboard gestures

One completed short/long gesture may wait behind an active text job, including
its final USB key release. It resolves the configured slot only when that job
has drained; it never overwrites the active password bytes or reserves another
text buffer. A subsequent completed gesture replaces the pending slot, matching
the legacy touch latch. Link reset, cancellation and another operation claiming
presence clear the pending gesture along with queued text. Regression tests
combine the real output policy and keyboard encoder with an independent HID
usage-table decoder, including `xy` followed by a mid-typing touch producing
`xyxy`, long-slot selection, no/empty touch, Enter and consumer Eject.
