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
