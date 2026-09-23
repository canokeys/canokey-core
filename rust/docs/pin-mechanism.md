<!-- SPDX-License-Identifier: Apache-2.0 -->
# Shared PIN mechanism

ADMIN, OpenPGP and PIV use `core/src/mechanisms/pin.rs`. This module owns
credential comparison and durable retry transitions. It has no APDU status words,
credential roles, session grants, crypto/KDF changes or default credentials.
OATH challenge-response remains a separate authentication mechanism.

## Boundaries

| Layer | Responsibility |
|---|---|
| `mechanisms/pin.rs` | Checked borrowed credential view, comparison without secret-dependent early exit, explicit charging mode, blocked/remaining/persistence results |
| `mechanisms/pin/record.rs` | ADMIN/OpenPGP version-1 68-byte record validation, creation, update, counter configuration, scoped loading and wiping |
| `applets/admin/pin.rs` | ADMIN record/default, 6–64 byte policy, fixed three retries, length-first error precedence |
| `applets/openpgp/pin.rs` | PW1/PW3/reset-code record selection, role lengths, configurable limits, domain-error mapping |
| PIV credential adapter in `applets/piv/pin.rs` | Eight-byte PIN/PUK policy, 24-byte atomic pair record, cached-state invalidation and APDU error mapping |
| Applet service/session | Revoke old grants before verification; issue a scoped grant only after success; reset/change/unblock and operation-specific consumption |

`Credential` borrows a mutable encoded record, a secret byte range, a counter
offset and a retry limit. Construction rejects invalid ranges, overlapping
counter/secret bytes, zero limits and counters above the limit. A synchronous
commit callback publishes the complete record atomically. No heap, global
buffer or extra persistent file is introduced. Input and record bytes must be
stable for the synchronous call; callbacks are storage-only and cannot re-enter
the session. PIV materializes just its existing 24-byte credential record.

## Preserve the existing charging policies

| Applet | Policy | Failed comparison | Successful comparison |
|---|---|---|---|
| ADMIN/PIV | `OnMismatch` | Compare, decrement, commit | Restore/commit only when retries differ from the limit |
| OpenPGP | `BeforeCompare` | Decrement/commit, then compare | Decrement/commit, compare, restore/commit |

The OpenPGP sequence deliberately charges interrupted attempts, including an
interruption before the comparison. This refactor preserves that implementation
choice; it does not assert that all applets have identical power-loss semantics.
A commit failure always returns `Persistence`, including a failed write that
would otherwise report remaining retries or successful verification.

ADMIN validates supplied length before loading or checking blocking. OpenPGP
loads and checks blocking before validating supplied length. PIV retains its
APDU validation before calling the mechanism. These different error priorities
stay in the adapters rather than becoming a configurable universal APDU policy.

## Storage and authorization

ADMIN/OpenPGP records remain exactly 68 bytes: version, length, remaining retries,
retry limit, and a 64-byte zero-padded credential area. ADMIN requires length
6–64 and limit 3. OpenPGP permits an empty disabled reset code, which creation
encodes with zero remaining retries. An empty credential remains disabled after
retry-limit changes. Credential replacement resets its retry count in the same
atomic write. Low-level creation rejects oversized values and zero retry limits
before writing, rather than risking a slice panic or an unreadable record.

PIV retains the version-1 24-byte combined PIN/PUK record. The verification
adapter serializes it, borrows only the selected credential and counter, then
wipes the encoding on every result. A failed commit invalidates its cache and
revokes both grants; recovery requires reload. The shared record adapter keeps
no cached credentials and wipes its local encoding after successful and failed
loads, verification and mutations. Session authorization is never serialized.

## Validation

Shared tests assert exact durable counter-write sequences for both policies,
correct and incorrect credentials, length mismatch, blocking and failure at
each commit (both committed and uncommitted failure outcomes). Record tests cover
layout, cleanup on errors, replacement, disabled reset codes, adjustable limits
and ADMIN error precedence. Existing PIV tests cover the compact-record adapter,
PIN/PUK changes, persistent blocking, session state and uncertain writes.

Run the Rust workspace tests with all features, feature-isolated tests, and the
existing ADMIN/OATH/OpenPGP host APDU suites. Build the independent DevKit
ADMIN/PASS, OpenPGP and PIV profiles with their mandatory boot/recovery gates.
No device-format migration or user credential reset is required.
