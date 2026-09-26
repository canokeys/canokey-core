<!-- SPDX-License-Identifier: Apache-2.0 -->
# Legacy test replacement ledger

Stage six removes a legacy test only after its behavior has executable Rust
coverage. The remaining C suite still builds alongside the complete Rust suite
with `ENABLE_TESTS=ON`; passing it does not establish Rust coverage. Reference
C tests can be inspected in core commit `1c64f28`.

## Replaced NDEF suite

The five cases in `test/test_ndef.c` are replaced by `core/tests/ndef.rs`:

| Legacy case | Rust regression |
|---|---|
| `test_ndef_cc_toggle_and_readback` | `selected_files_permissions_and_poweroff`, `capability_cache_reload_missing_file_and_recovery` |
| `test_ndef_cc_write_error_invalidates_cache` | `uncertain_permission_commit_reloads_and_failed_load_is_closed` (both applied and unapplied failing writes) |
| `test_ndef_cc_reload_failure_rejects` | `uncertain_permission_commit_reloads_and_failed_load_is_closed`, `capability_cache_reload_missing_file_and_recovery` |
| `test_ndef_cc_read_served_from_cache` | `capability_cache_reload_missing_file_and_recovery` (counts backing reads, including message reads) |
| `test_ndef_read_bounds` | `capability_cache_reload_missing_file_and_recovery`, `pulled_response_reads_all_1024_bytes_without_an_object_buffer` |

The new cases use the Rust NDEF Store boundary to distinguish failures before
and after commit. Production LittleFS byte operations remain native and are
separately exercised by `native-storage` (`tools/hil/test_rust_storage.py` in the
CIU parent checkout), using the real service adapter and LittleFS with mock
Flash. Rust host snapshots are not evidence for LittleFS power-loss durability.
Registry tests additionally verify selection, chained writes and streamed reads
through the actual APDU engine.

## Replaced keyboard suite

The seven cases in `test/test_kbdhid.c` are replaced by
`core/src/applets/pass/output_regressions.rs`, combining the actual output and
keyboard policies with an independent HID usage-table decoder:

| Legacy case | Rust regression |
|---|---|
| `test_typing_full_charset` | `full_charset_enter_and_consumer_eject` |
| `test_typing_with_enter` | `full_charset_enter_and_consumer_eject` |
| `test_eject_sequence` | `full_charset_enter_and_consumer_eject` |
| `test_no_touch_no_output` | `touch_routing_empty_slot_and_no_touch` |
| `test_touch_consumed_and_routed` | `touch_routing_empty_slot_and_no_touch` |
| `test_empty_sequence_types_nothing` | `touch_routing_empty_slot_and_no_touch` |
| `test_pending_touch_waits_for_current_sequence` | `completed_touch_waits_for_text_and_final_key_release` |

The pending-touch port exposed and fixed a lost gesture in the Rust output
policy. `pending_gesture_is_cleared_by_cancel_and_tracks_long_slot` additionally
checks cancellation and long-slot selection. Packet completion and controller
behavior remain covered by the USB/keyboard adapter tests.

## Replaced native key-stream boundary test

`test_key_stream.c::test_encode_mldsa_stream_cleanup` injected nine primitive
return/phase combinations into the old C public-key encoder. The replacement
`core/tests/stream_crypto.c` exercises the production crypto adapter (the
primitive-only native exception), with all nine cases plus short initial output,
wrong initial phase and an oversized second stage. It reads in 127-byte chunks,
checks canaries/seed immutability and verifies exactly-once native abort, including
repeated cleanup. The port exposed missing stage-length/phase validation in the
new adapter; invalid keygen results now fail before being published. The Rust
PIV host suite separately verifies real PQ public keys, signatures and recovery
after aborted streams; the native test is not a replacement for those policies.

## Replaced OATH/PASS suite

All 18 cases in `test/test_oath.c` now have correctness replacements:

| Legacy case | Rust regression |
|---|---|
| `test_select_ins` | `oath-normal`: SELECT fields and persisted handle |
| `test_invalid_ins` | `virtual-oath-regressions`: unsupported INS |
| `test_put` | `oath-normal`: SHA-1/256/512 creation; `virtual-oath-regressions`: duplicate and increasing-only creation |
| `test_put_long_key` | `virtual-oath-regressions`: literal FF KEY declaration, 6A80 |
| `test_put_unsupported_algo` | `virtual-oath-regressions`: literal unsupported algorithm |
| `test_put_unsupported_counter` | `virtual-oath-regressions`: TOTP initial-counter rejection |
| `test_calc` | `virtual-oath-regressions`: original short-challenge digest, decreasing ordinary TOTP, missing/truncated/invalid challenge |
| `test_increasing_only` | `virtual-oath-regressions`: equal/increasing accepted, decreasing rejected |
| `test_counter_write_failures_do_not_return_otp` | `virtual-oath-regressions`: HOTP, increasing-only and PASS failed counter commits, empty response and counter recovery |
| `test_list` | `oath-normal`: ordered listing and A5 pagination |
| `test_calc_all` | `oath-normal`: full/truncated paginated results; `virtual-oath-regressions`: malformed challenge |
| `test_hotp_touch` | `virtual-oath-regressions`: RFC 4226 counters 1..10, both slots, initial counter, binding config and deletion |
| `test_static_pass` | `virtual-oath-regressions`: maximum length, oversize, Enter and reset persistence |
| `test_pass_hmacsha1_config` | `virtual-oath-regressions`: configured/disabled slots, suppressed typing and persistence |
| `test_oath_yk_hmacsha1_api` | `virtual-oath-regressions`: short/padded independent HMAC, missing slot and serial |
| `test_tombstone_reuse` | `virtual-oath-regressions`: delete/reinsert does not grow the live record |
| `test_regression_fuzz` | `virtual-oath-regressions`: fixed malformed TLVs with explicit statuses; no mutation campaign |
| `test_space_full` | `repository::tests::capacity_exceeds_one_hundred_and_reserves_delete_and_reinsert_space` |

Capacity coverage checks more than 100 records, finite-capacity rejection with
an unchanged image, the 64 KiB reserve, deletion and reinsertion after rejection,
and every surviving credential. Staging counts both old and new images. The
production native LittleFS adapter separately checks exact reserve boundaries
and oversized arithmetic through `native-storage`; a mock is not a physical
Flash power-loss oracle.

KEY and challenge declarations preserve the legacy 6A80 semantic-length
precedence while using bounded reads for 6700 truncation. The previously noted
FF KEY compatibility difference is resolved.

## Still requiring individual coverage audit

Four C test executables remain, with 190 registered cases: APDU (91),
key (25), OpenPGP (16), PIV (58). Their C applet/protocol dependencies
remain until each case is mapped or ported. This ledger is not a completion
certificate for stage six, production capacity, stack or interoperability.

Fuzz campaigns, corpus replay and coverage-guided test harnesses are removed.
Literal malformed-input regressions remain correctness tests with explicit
expected results; they do not run mutation campaigns.

## Public helper audit

The helper audit exposed missing foreign HID progress and overly restrictive
CCID/WebUSB takeover. Both are corrected and tested through the real Rust USB
composition. `test_core_helpers.c` and its GNU-ld wrapper target are now removed;
all 13 original cases are mapped in the sections below.

## Replaced public-helper cases

Eight of the 13 old helper cases have now been removed individually:

| Legacy case | Executable replacement |
|---|---|
| `test_tlv_get_length_safe_variants` | `legacy_length_vectors_require_complete_values_at_finish` (all split positions, complete and truncated BER values) |
| `test_fs_roundtrip_and_metadata` | `native-storage`: write, atomic append, offset read, truncate/extend, rename, remount and reserve; Rust PIN `codec_replacement_and_cleanup_preserve_record_contract`: version/length/retry metadata and atomic replacement |
| `test_fs_error_paths` | `native-storage`: missing record, UINT32_MAX offset rejection, canaries, injected program failure and unchanged committed record after remount |
| `test_wait_for_user_presence_ok` | `ordinary_prompt_restores_idle_on_success_timeout_and_cancellation`, `failed_wait_still_claims_gesture`, `claimed_gesture_is_not_replayed_after_wait` |
| `test_wait_for_user_presence_services_ctaphid_while_ccid_waits` | `hid-usb` foreign busy/INIT/CANCEL isolation; `usb-device` real progress dispatch under a CCID extension lease |
| `test_wait_for_user_presence_cancel_and_timeout` | `ordinary_prompt_restores_idle_on_success_timeout_and_cancellation`; `hid-core` actual execution cancellation/disconnect |
| `test_strong_user_presence_test_success_and_failure` | `strong_presence_requires_five_released_gestures_and_services_gaps` |
| `test_device_loop_and_nfc_state` | `device-runtime`: actual Rust main loop USB dispatch and NFC mode transition/reset, all ten boot scenarios |

LittleFS attributes are not a new native policy API: Rust stores PIN and key
metadata together with the value in versioned records. The codec tests check
that replacement contract; the native fixture checks opaque byte persistence.
Unsigned offsets reject UINT32_MAX, the former negative-offset error case.
No claim about physical Flash power-loss durability follows from these mocks.

## Replaced session/keepalive helper

`test_device_sessions_and_keepalive` is now removed. The `usb-sessions` fixture
covers same-owner grant retention, idle lease expiry and tick wraparound,
foreign busy rejection, completed CCID/WebUSB immediate takeover, HID lease
protection despite queued foreign traffic, reset revocation and stale WebUSB
cleanup isolation. `hid-usb` verifies both processing and presence keepalive
reports with asynchronous IN ownership; `hid-core` exercises actual presence
execution/cancel/disconnect. These replace the old helper's mocked counters.

Source-aware admission now additionally permits abandonment of OpenPGP
certificates, PIV object cursors/crypto streams/attestation, large OpenPGP/PIV/NDEF
results and large CTAP/U2F registration responses. The sizes and backing rules
are documented in `device.md`. The actual USB fixture verifies unread CTAP,
OpenPGP certificate and PIV object takeover, rejection for PIV Discovery, stale
GET RESPONSE rejection and PIN-grant revocation. The NDEF engine fixture checks
large-read admission; streaming engine tests retain input-chain protection.
The other four helper cases are mapped below. Production capacity, stack and
physical interoperability are still independent, incomplete acceptance items.

## Replaced LED, touch and PIN helper cases

| Legacy case | Executable replacement |
|---|---|
| `test_device_blinking_and_led_behaviour` | `ordinary_prompt_restores_idle_on_success_timeout_and_cancellation`: exact initial LED phases, timeout tick and restoration; strong-presence phase/gap tests; `device-runtime` normally-on/off settings and timer cancellation/rearming |
| `test_device_allow_kbd_touch_rules` | `startup_contact_release_and_short_long_boundaries`: startup hold/release, 29/30 ms debounce and 499/500 ms slot boundary; `claimed_gesture_is_not_replayed_after_wait` and pending-output inhibition tests |
| `test_pin_lifecycle` | `codec_replacement_and_cleanup_preserve_record_contract`, `record_lifecycle_blocking_and_storage_errors`; `core-normal` PIN-change grant revocation; `openpgp-normal` maximum retry policy and 63CF queries |
| `test_pin_error_paths` | PIN missing/failing-store, invalid-length and permanent-block unit tests; `no_success_after_any_failed_commit`; `openpgp-normal` all three retry-policy fields reject 0/16 without losing the current grant |

The removed generic blink scheduler is no longer a production API. Rust presence,
boot and wink callers own their LED policy; tests verify those callers' timing
and idle restoration instead of preserving counts of redundant C LED writes.
The disabled OpenPGP reset code retains its retry policy in a versioned record
but cannot authenticate; this replaces the old `pin_clear` attribute layout.
Generic Rust retry storage is not limited to 15: the OpenPGP wire policy enforces
1..15 and ADMIN uses its fixed limit. No obsolete C helper API was recreated
just to keep an internal-layout assertion passing.

## Replaced APDU transport/session cases

Five of the original 96 `test_apdu.c` cases are now retired:

| Legacy case | Executable replacement |
|---|---|
| `test_ccid_power_on_preempts_idle_webusb_session` | `usb-sessions`: real PowerOn/PowerOff takeover, ATR/inactive status, grant revocation, partial-response exclusion and stale cleanup isolation |
| `test_applet_session_deadline_wraparound` | `usb-sessions`: actual 1999/2000 ms cross-interface admission across uint32 tick wraparound |
| `test_get_response_after_reset_without_pending_response` | `core-normal`: 6986 without a pending response; `usb-sessions`: direct GET RESPONSE after takeover and reset |
| `test_pending_ccid_response_can_be_abandoned_by_ctaphid` | `usb-sessions`: unread real CTAP GetInfo source is abandoned immediately by HID PING after CCID IN completion; protocol response tests check exactly-once close |
| `test_active_ccid_transfer_cannot_be_preempted` | `usb-sessions`: same source rejects HID PING while CCID IN owns its packet, verifies unchanged bytes, then permits takeover after completion |

The first port exposed missing PowerOn/PowerOff admission in Rust's WebUSB
preemption gate. Slot-status discovery alone still does not request takeover.
Other APDU cases remain registered until their coverage is individually mapped.
