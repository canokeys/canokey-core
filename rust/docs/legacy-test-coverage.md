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

One legacy C test executable remains, with 39 registered APDU cases.
Its C applet/protocol dependencies remain until each case is
mapped or ported. The independent `test_fs` retains ten allowed native LittleFS
helper cases and has no applet/protocol/crypto/device-simulator linkage. This ledger is not a completion
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

## Replaced response continuation cases

Seven more APDU cases are retired after exercising the Rust response cursor and
actual applets through the same-pointer RX/TX FFI:

| Legacy case | Executable replacement |
|---|---|
| `test_response_source_multi_chunk_get_response` | `core-normal::aliased_response_regressions`: all 600 certificate bytes across varying chunk capacities; `streaming::generated_response_does_not_reexecute_operation`: one generation and one close |
| `test_response_source_tail_restore_on_shared_buffer` | `core-normal::aliased_response_regressions`: request overwrites, status trailers, payload comparison and output canaries |
| `test_response_source_read_failure_clears_state` | `response::tests::invalid_reads_wipe_requested_window_and_end_the_lease`: failed, zero and excessive reads, output wiping, status and exactly-once close |
| `test_apdu_output_chaining_aliased_buffer` | `core-normal::aliased_response_regressions`: first payload lengths 248/247/1/0, subsequent 256/200-byte chunks |
| `test_new_command_abandons_pending_rapdu_chain` | `core-normal::ordinary_response_cleanup_regressions` and `aliased_response_regressions`: PIV VERSION and OpenPGP certificate abandoned by SELECT ADMIN / READ_VERSION, then 6986 |
| `test_session_reset_drops_pending_rapdu_chain` | Both `core-normal` regressions: reset with zero/partial progress under CCID/NFC ownership, then 6986 |
| `test_response_source_clear_calls_close` | `response::tests::short_reads_preserve_offsets_status_and_exactly_one_close`: completion and repeated clear close once |

Rust keeps response backing separate from transport bytes; it does not need the
old C shared-buffer tail-restore algorithm. The actual FFI regressions overwrite
the RX/TX buffer between calls and verify every returned byte. Rust's established
absent-Le default is 256 rather than the old C zero; bounded output capacities
exercise zero-progress responses without changing that wire policy. Chunk
boundaries may differ from the old 250-byte source path. These tests establish
byte/status/lifetime correctness, not physical transport interoperability.

## Replaced FIDO input boundary and host reboot cases

| Legacy case | Executable replacement |
|---|---|
| `test_fido_apdu_chain_overflow_returns_wrong_length` | `streaming::fido_chain_exact_limit_overflow_and_recovery`: actual Core accepts exactly 1024 bytes, rejects byte 1025 with 6700, releases the chain lease and executes a fresh getPinRetries under both CCID and NFC owners |
| `test_fido_magic_reboot_after_reset_without_select` | `virtual-pcsc`: real IFD reset followed immediately by the host-only magic reboot APDU returns 9000 without selecting an applet |

The Rust CTAP parser consumes ISO fragments incrementally; it does not retain
an accumulated PKE request or expose the former C PKE owner flag. The boundary
regression checks the actual runtime lease and a new successful command after
rejection. Standalone extended PKE input remains separately covered by
`extended_fido_source_is_bounded_and_ccid_only` and the USB fixtures. Magic reboot
is a host compatibility control, not a production firmware APDU extension.

## Replaced ADMIN certificate and SM2 configuration cases

| Legacy case | Executable replacement |
|---|---|
| `test_admin_chained_fido_cert_write` | `ctap-config` with `ctap_fixture.provision`: real multi-fragment certificate provisioning, exact x5c bytes and independently verified signatures; rejects chained READ_VERSION with 6E00 |
| `test_admin_sm2_config_validation` | `ctap-config`: all 13 reserved curves, three reserved algorithms, all ten allowed curves, unauthorized write and unchanged config after each rejection |
| `test_admin_sm2_config_wire_format` | `ctap-config`: all four literal BE32 vectors, including both INT32 extremes; reset/re-authentication, exact persisted readback, decoded GetInfo algorithm and 7/9-byte rejected writes preserving state |

The certificate regression uses a real certificate larger than 528 bytes rather
than the old five-byte placeholder. It verifies the complete resulting bytes
through CTAP attestation, not an internal native filename. SM2 configuration is
an opaque eight-byte Rust record; byte round trips are supplemented by decoded
GetInfo identifiers and the existing custom-curve credential/signature checks.

## Replaced ADMIN public configuration and reporting cases

| Legacy case | Executable replacement |
|---|---|
| `test_admin_platform_config_and_serial_apdus` | `core-normal`: unauthorized writes, invalid selectors/lengths, LED/NDEF/WebUSB and feature changes surviving reset, disabled applet routing, one-time serial write/read and short-Le rejection |
| `test_admin_read_core_commit_apdu` | `core-normal`: full host revision, truncated public fields, no pending continuation and invalid P1/P2 |
| `test_admin_flash_usage_apdus` | `core-normal`: total and eight-record APDU shape/length/selectors; `groups_use_big_endian_bytes_and_system_overhead`: every record group, missing flags, seven added PIV bytes, stable system overhead and read/capacity failures |
| `test_admin_kbd_keymap_apdus` | `core-normal`: missing map, invalid write selector/255-byte length, full streamed 256-byte map, layout ID, exact readback and real keyboard lookup, invalid read/clear requests, reset persistence and clear restoring default mapping |

The host revision is the native information provider's `unknown`, not a C build
macro. Firmware board-information plumbing is separately exercised by the device
adapter tests. Usage attributes versioned Rust records rather than legacy file
names and LittleFS attributes. Missing flags describe missing records in that
namespace; native storage tests separately verify physical capacity reporting.

## Replaced reselection, configuration preservation and routing cases

| Legacy case | Executable replacement |
|---|---|
| `test_openpgp_ccid_idle_timeout_preserves_pin_on_reselect` | `usb-sessions`: actual CCID PW1 verification, 2001 ms idle, same-app SELECT/query success, foreign WebUSB takeover and revoked PW1 |
| `test_piv_reselect_preserves_security_status` | `usb-sessions`: real PIN verification, full and RID-only reselect/query success, applet switch and revoked PIN |
| `test_platform_config_flags_preserve_other_state` | `admin_flags_preserve_initialization_nfc_and_identity`: exact flag mask, initialized/NFC state, serial, CRC and every non-flag/non-CRC page byte |
| `test_virt_card_config_page_persistence` | `virtual-storage::configuration_snapshot_reopens_and_explicit_reset_erases_it`: 512-byte page survives reopening; explicit reset persists an erased page |
| `test_runtime_feature_apdu_routing` | `independent_transport_bits_and_failed_reads_guard_actual_select`: independent USB/NFC masks reject actual PIV/OpenPGP SELECT; `core-normal`: restored successful selection/read, disabled implicit FIDO and reset persistence |

The virtual card uses the Rust host snapshot rather than the removed C sidecar
format. These are host persistence tests; physical configuration-page writes
and Flash power-loss durability require separate hardware acceptance.

## Replaced SELECT, HID response-source and GetInfo cases

| Legacy case | Executable replacement |
|---|---|
| `test_select_and_read_command_validation` | `core-normal::select_validation_regressions`: ADMIN suffix/class/data, SELECT P2 precedence, all legacy PIV AID forms and invalid partial/version forms, OATH class rejection |
| `test_ctaphid_rejected_source_closes_once` | `response_limits_and_read_failure_close_once`: CBOR/MSG/WINK reject 7610, 65536 and usize::MAX lengths, one request/response close, repeated reset/completion cannot close again |
| `test_ctaphid_active_source_failure_closes_once` | Same Rust regression: source read failure closes once; successful lengths 0/1/57/58/7609 verify every payload byte, sequence and ownership through final completion |
| `test_ctap_get_info_reports_transport_msg_size` | `ctap-normal` and `virtual-hid-udp`: decoded GetInfo key 5 equals 1024 on real APDU/HID routes |

The port exposed two compatibility gaps: Rust accepted invalid PIV AID prefix
lengths and did not bound response-source lengths before HID transmission. Both
are corrected. HID's 7609-byte response framing bound is independent of its
1024-byte request policy; rejecting only lengths above UINT16_MAX was insufficient.

## Replaced OpenPGP PIN, data and certificate cases

Nine of the 16 original OpenPGP cases now have real Rust APDU replacements:

| Legacy case | Executable replacement in `openpgp-normal` |
|---|---|
| `test_verify` | `pin_regressions`: successful PW1, short length, two wrong values then permanent block |
| `test_reselect_preserves_pin_authorization` | `pin_regressions`: verified PW1/PW3 survive SELECT and status queries |
| `test_change_reference_data` | Invalid P1, short new PIN, incorrect old PIN, successful change and authentication with the new value |
| `test_reset_retry_counter` | Admin-reset denied without PW3, reset-code recovery, new PW1 authentication |
| `test_set_pin_retries` | Unauthorized and short/long requests, all 0/16 field boundaries, limits 4/5/6 and 15/15/15, disabled RC status and exact retry queries |
| `test_set_pin_retries_failure_invalidates_auth` | Test-only one-shot record-write failure at PgpPw3 after earlier writes: 6900, subsequent F2 denied with 6982, authentication recovery |
| `test_get_data` | Application-related DO parsed and its AID checked |
| `test_algorithm_information` | Exact FA encoding of all 24 supported algorithm attributes across SIG/DEC/AUT; no duplicate-tag dictionary loses entries |
| `test_openpgp_cert_chained_read` | Three 1024-byte patterned certificates written over command chaining and fully compared after GET RESPONSE |

The port exposed F2's invalid-length status difference, now corrected to 6700.
Fault injection is a test-only native storage seam, not a firmware command or
presence bypass. It models a rejected write and tests authorization cleanup;
it does not claim physical power-loss durability or atomicity across PIN records.

## Replaced OpenPGP key cases

Five additional cases now run through actual Rust APDUs in
`openpgp-normal::key_regressions`:

| Legacy case | Replacement |
|---|---|
| `test_import_key` | Malformed attributes, fixed Ed25519 seed with/without an ignored supplied public component, independent public-key and signature verification |
| `test_import_rsa_rejects_inconsistent_crt` | Corrupted dp and equal-prime imports return 6A80; the previous valid RSA key still signs correctly after each rejection |
| `test_generate_key` | Generation denied without PW3, authenticated RSA generation, short decipher input returns 6700 |
| `test_decipher_chaining` | Exact 254/3-byte zero-ciphertext fragments return 9000/6A80, followed by independently encrypted successful decryption |
| `test_x25519_public_key_encoding` | Literal big-endian imported scalar and complete expected 7F49 public-key encoding, plus independent shared-secret verification |

The port exposed two compatibility defects: invalid RSA padding was collapsed
into generic crypto failure, and the OpenPGP X25519 import incorrectly reversed
the scalar (the PIV convention). The primitive adapter now reports padding
failure distinctly and Rust maps it to 6A80; other crypto failures remain 6900.
OpenPGP keeps its big-endian private scalar. The randomized host import helper
now encodes that convention independently instead of agreeing with the defect.
Extended-APDU and termination/cache cases remain in the C suite pending audit.

## Final OpenPGP suite replacement

The last two cases in `test/test_openpgp.c` are now replaced and that executable
is removed. Its native applet still has callers in the remaining APDU/key suite.

| Legacy case | Executable replacement |
|---|---|
| `test_special` | `openpgp-normal::extended_key_regressions`: literal extended 0047/81 and 0047/80 envelopes, missing-key status, generated/read public-key equality after GET RESPONSE, independently verified signature |
| `test_terminated_cache` | `lifecycle_cache_reloads_uncertain_commits_and_revokes_grants`: install/activation cache priming, zero backing reads for active AID and terminated rejection, successful termination, unapplied/applied failing commits, failed reload, authorization revocation, interrupted activation, metadata-write invalidation and transport reset |

Rust now admits extended OpenPGP envelopes on CCID/NFC under the existing
transport ownership and bounded command rules. The old `test_special` only
printed results; its replacement asserts them. The lifecycle cache is local to
the selected applet, discarded on reset/reselection through another applet and
invalidated before state-record mutation. A failed terminate clears grants and
forces a durable reload: neither success nor failure of a write is guessed.
The storage fixture models both commit outcomes and counts actual trait reads;
physical LittleFS power-loss behavior remains a separate acceptance item.

## Replaced HID ingress, timeout and echo cases

| Legacy case | Executable replacement |
|---|---|
| `test_ctaphid_out_event_only_enqueues` | `hid-core::mailbox_regressions`: no protocol output before main-loop service |
| `test_ctaphid_rx_high_water_pauses_and_resumes` | Same regression: full mailbox rejects overwrite, holds receive until consumed, then rearms and accepts new input; `hid-usb` additionally injects IRQs during consumption |
| `test_ctaphid_uses_receive_tick_for_timeout` | Actual Rust mailbox/core: initial frame at 100 ms, continuation received at 700/1000 ms, both dispatched at 1100 ms; exact echo/timeout outcomes |
| `test_ctaphid_cancel_is_consumed_from_queue` | `hid-core`: real selection command receives queued owner CANCEL and returns CTAP cancellation; `hid-usb`: queued cancellation while keepalive IN remains owned, foreign CANCEL isolation |
| `test_ctaphid_sustains_fifty_reports` | `hid-core::mailbox_regressions`: 50 distinct one-byte echo reports, byte/order/count checks through each receive rearm |
| `test_ctaphid_large_ping_is_consumed_incrementally` | `hid-core` and `ping_boundaries_and_monotonic_source_lifetime`: 192/193/1024/1033/1288/3072-byte echoes, full byte comparisons, monotonic reads and wiped/released PKE leases; capacity+1 rejected before acquisition |

Rust uses one held USB OUT mailbox instead of the former eight-entry C queue;
controller backpressure prevents accepted USB reports from being overwritten.
The regression uses that admission/rearm contract rather than demanding the old
internal queue depth. Cancellation is tested during actual execution, not via
the removed C loop return code after a completed PING.

Porting the large-echo case exposed a functional reduction: Rust had applied
the 1024-byte CTAP CBOR request policy to PING. PING now uses the actual staging
capacity (or inline capacity), capped at HID's 7609-byte framing maximum.
CBOR/MSG still enforce their independent 1024/1033-byte admission policies;
all staged commands check storage capacity before acquiring it. No additional
firmware buffer or persistent staging was introduced.

## Replaced CCID header and HID descriptor cases

| Legacy case | Executable replacement |
|---|---|
| `test_ccid_le32_wire_encoding` | `header_length_is_unaligned_little_endian_without_native_layout`: literal 78563412 length, all ten response bytes; the old C struct-offset assertions are replaced by byte encoding with no native struct ABI |
| `test_ccid_response_headers` | `literal_discovery_and_rejected_command_headers`: all original request/slot pairs and four additional rejected-slot families, complete literal headers, exact ATR/T=1 payloads and lengths |
| `test_hid_setup_descriptors_and_errors` | `hid_descriptor_bytes_short_reads_and_unknown_class_requests`: both literal nine-byte HID descriptors, report lengths and prefixes, four-byte control transfer, SET_IDLE and unsupported-class stall |

The CCID port found incorrect response-family selection when a bad slot bypassed
parameter dispatch, and for unsupported Secure/Escape commands. The family and
protocol-number field now come from the request before validation. Existing Rust
corrections are retained explicitly: successful bError is zero (the old C fixture
expected 81), ResetParameters returns T=1 parameters, empty SetParameters fails
validation, and unsupported commands set the command-failed status with bError
zero. Returning success for unsupported operations is not retained. These are
intentional protocol corrections, not claims of byte identity to every old C
response. The actual endpoint/EP0 stall lifecycle remains covered by USB adapter
fixtures; these tests exercise the Rust wire and policy boundaries.

## Replaced key encoding and scalar streaming cases

| Legacy case | Executable replacement |
|---|---|
| `test_encode_rsa` | OpenPGP/PIV `encoding_regressions`: original RSA-4096 p/q and complete 522-byte public encoding preserved in `vectors/rsa4096-public.json`; actual import/read/use with independently completed CRT |
| `test_encode_ecdsa` | Both APDU suites import the original P-256 private scalar, compare the entire canonical SEC1/TLV public value and independently verify operations |
| `test_encode_p521_length` | Strict `key_test.pubkey` checks all P-521 generated/imported values have the exact 86818504 prefix and 136-byte inner length; both suites assert canonical outer 7F49 lengths |
| `test_encode_eddsa` | RFC 8032 fixed seed/public encoding on both APDU routes, plus literal RFC 7748 public output and independent signature/agreement checks |
| `test_encode_mldsa` | PIV `encoding_regressions`: original zero/FF/two patterned seeds, all 1952 public bytes independently derived, exact 868207a0 prefix and repeated metadata streaming; native stream canaries/seed immutability remain in `stream-crypto` |
| `test_parse_openpgp_x25519_streaming_rfc7748` | Alice's clamped big-endian scalar imported in seven-byte APDU fragments, exact RFC public encoding and independent shared secret |
| `test_parse_piv_x25519_streaming_rfc7748` | Alice's clamped little-endian scalar using tag 08 in five-byte APDU fragments, same public value and shared-secret check |
| `test_tlv_len_stream_feed` | `tlv::length::tests`: sequential 7F/81-80/82-0102/20 lengths and rejected 80/83 forms, plus full decoder truncation regressions |

The old P-256 encoder fixture supplied a public point unrelated to its private
scalar. Its replacement uses a literal public point independently derived from
the original scalar, enabling real import and signature verification. The old
X25519 encoder similarly copied arbitrary stored public bytes; RFC 7748 tests
now exercise actual derivation and both applets' distinct private-wire formats.
Strict decoding additionally rejects noncanonical widths/lengths, duplicate or
extra public fields instead of merely extracting a valid key from them. Native
key storage/error paths are mapped below; native PIN and LittleFS cases remain.


## Replaced key import bounds and compact ECC storage

| Legacy case | Executable replacement |
|---|---|
| `test_parse_piv_rsa_rejects_invalid_component_bounds` | `piv-normal::import_boundary_regressions` rejects empty/oversized RSA integers and unexpected next tags with 6A80, preserves the old key; `import::tests::rsa_component_boundaries_do_not_overwrite_the_next_component` tests every input split with canaries and bytewise component transitions |
| `test_parse_piv_policies_rejects_truncated_fields` | `piv-normal::import_boundary_regressions` submits AA/AA01/AB/AB01 to both GENERATE and IMPORT, checks 6700, identical metadata and a subsequent independently verified private operation |
| `test_ecc_key_persists_only_ecc_material` | `compact-storage` imports P-521 into OpenPGP and PIV, checks exact 31+66 / 6+66 record sizes, resets the engine, compares public keys and independently verifies signatures |

The C parser test fabricated an internal `comp_off == comp_len` Value state.
Rust keeps these fields private and transitions to Tag immediately after the
last component byte. The replacement checks that reachable transition and
ensures neither malformed input nor fragmentation crosses the next component's
boundary. No unsafe internal-state mutation is exposed for compatibility.

Rust ECC records contain only the private scalar and metadata; public points
are derived after reload. The old 198-byte native ECC-structure persistence
contract is intentionally replaced by the compact record contract, with actual
post-reset private-key use rather than comparing unused structure padding.


## Replaced invalid and absent key record cases

| Legacy case | Executable replacement |
|---|---|
| `test_encode_invalid_type` | `protocol::key_record_tests::truncated_seed_and_invalid_key_types_never_reach_crypto`: stored algorithms 12 (PKC end), 14 (AES-128) and FF rejected at metadata validation; the crypto backend panics if invoked |
| `test_read_key_rejects_short_material` | Same test submits a 63-byte ML-KEM seed record to GET METADATA, checks 6900, no material read/crypto, no response body and an entirely zero key/output workspace |
| `test_read_empty_key_ignores_stale_material` | `absent_keys_and_stale_origin_zero_records_never_load_material`: missing/zero-sized records return 6A88, an origin-zero record containing stale material returns 6900; none reads material or reaches crypto and all clear the key workspace |

Rust does not persist a native origin-zero metadata structure alongside stale
key bytes. Missing/empty records represent absence; a nonempty record must have
origin 1 or 2 and an exact validated length. Rejecting origin-zero stale records
is intentional corruption handling, not preservation of the C storage format.

`partial_scalar_and_each_rsa_component_read_failure_clear_the_workspace` also
injects a prefix write followed by a read error for P-521 and each exponent/CRT
component of RSA-2048/4096. These checks execute PIV begin/finish, including the
real command cleanup boundary. The shared low-level loader may contain partial
material on failure; its caller owns wiping. No duplicate loader wipe or extra
production buffer is introduced. These fixtures test cleanup and rejection;
actual valid key derivation/use remains independently checked by APDU suites.


## PIN batching and independent LittleFS tests

`test_pin_batched_retry_updates` is replaced by Rust
`mechanisms::pin::tests::records::batched_retry_updates_and_failed_restore_preserve_the_record`
and the existing `record_lifecycle_blocking_and_storage_errors`,
`retry_policies_preserve_exact_write_sequences`, `no_success_after_any_failed_commit`
and PIV authorization/retry tests. Coverage includes one replacement containing
secret and both counters, no write on ordinary successful verification, decrement
and restore commits, failed restore rejection/recovery, blocked correct PIN,
missing/incomplete records, and atomic change/clear with persisted policy.
The record fixture counts backend replacements; LittleFS physical commit and
fault recovery remain separately checked by the native helper suite. OpenPGP's
prepaid-attempt policy has intentionally different successful-verification writes
and retains its dedicated tests.

`test_key.c` is retired. Its ten filesystem cases live in `test_fs.c`, compiled
with only `src/fs.c`, `littlefs/lfs.c`, `littlefs/lfs_util.c` and
`littlefs/bd/lfs_filebd.c`. A one-shot file-error fixture replaces the virtual
card simulator hook. There is no link to `canokey-core`, crypto, the USB dummy,
or device simulation. Sanitizers and fatal UBSan remain enabled. The standalone
suite preserves file/attribute operations, commit validation and uncertain
outcomes, reader ownership/cache cleanup, injected block failures and mutation
generation. These are allowed LittleFS thin-adapter correctness tests, not
remaining native applet functionality.


## Replaced clientPIN length and token timing cases

| Legacy case | Executable replacement |
|---|---|
| `test_client_pin_encrypted_length_policy` | `client_pin::tests::encrypted_pin_length_policy_is_identical_at_every_fragment_boundary`: protocols 1/2, SET/CHANGE, lengths 0/expected-1/expected/expected+1/expected+16/240 at every two-fragment split including whole-buffer input |
| `test_pin_uv_auth_token_timer_wraparound` | `config::tests::token_authorization_refresh_and_expiry_follow_successful_uses_across_wrap` runs successful authorization across wrap for both protocols; `pin::tests::token_expiry_checks_idle_and_absolute_limits_across_clock_wrap` checks exact idle/absolute boundary pairs |
| `test_pin_uv_auth_token_invalid_auth_does_not_refresh_timer` | Authorization regression submits a bad MAC at 20 seconds and a correct MAC at 30001 ms, checks unchanged last-use time, rejection, token wipe and no storage writes |
| `test_pin_uv_auth_token_max_lifetime` | Authorization regression successfully authenticates every 29 seconds, verifies only last-use changes, then rejects exactly at 600000 ms and wipes token/permissions; repeated near u32 wrap |

The incremental Rust parser replaces both native contiguous/source-backed
parsers. Exact-size encrypted PIN values proceed to missing-parameter checks;
undersized values return invalid CBOR, oversized values PIN policy violation.
Token timing tests use a controlled MAC backend to isolate authorization policy;
independent protocol encryption/MAC compatibility remains in `ctap-normal`.


## Replaced authenticator policy/GetInfo cases

| Legacy case | Executable replacement |
|---|---|
| `test_ctap_config_toggle_always_uv_without_pin` | `ctap-normal` toggles alwaysUv without a PIN, checks clientPin/alwaysUv and U2F_V2 advertising, resets and verifies persisted GetInfo, then disables the policy and compares the original full GetInfo |
| `test_ctap_hid_get_info_with_force_pin_change_is_canonical` | `ctap-normal` authenticates a forcePINChange configuration, checks flag 12 and exact canonical CBOR re-encoding, resets and compares the full response, checks token refusal, changes the PIN and verifies flag clearing |

Every `ctap-normal` GetInfo reply now must exactly equal independently
re-encoded canonical CBOR, including complete consumption (no trailing bytes)
and ordered maps. The native test directly mutated a force-change flag; the
replacement configures it through the authenticated production APDU path.
GetInfo uses the shared Rust CTAP encoder on HID and APDU; endpoint framing
continues to be checked by `hid-core`, while these regressions exercise policy,
encoding and reset persistence. They do not claim physical HID interoperability.


## Replaced NDEF streaming and empty configuration cases

| Legacy case | Executable replacement |
|---|---|
| `test_ndef_chained_update_and_streaming_read` | `ndef::apdu::actual_registry_selection_chained_updates_and_streamed_read`: original bytes at offset 20, continuation P1/P2=03FF, exact 300-byte streamed response, 1024-byte streaming, reset selection and repair of a 32-byte record with a cross-boundary read; installation test checks all repaired padding is zero |
| `test_ctap_config_empty_request_is_legacy_unhandled` | `ctap-normal` submits bare 0D and checks F1; `config::tests::malformed_config_has_no_persistent_effects` additionally distinguishes no body, truncated map (12), empty map (14), and verifies no writes |

The NDEF regression exposed a runtime integration discrepancy: the generic
header matcher restarted UPDATE when a later fragment changed P1/P2. NDEF's
write cursor must keep the first fragment's offset. The registry now normalizes
only NDEF UPDATE offsets for chain identity; the original header still reaches
the applet, other instructions and applets retain normal header matching, and
the shared command limit/session lifecycle remain unchanged. The streamed read
uses the Rust transport's response chunk size rather than the obsolete C
250-byte internal window; requested length and content remain exact.
Bare authenticatorConfig now explicitly preserves the legacy F1 status.


## Replaced PIV management authentication and object authorization cases

| Legacy case | Executable replacement |
|---|---|
| `test_piv_aes192_mutual_authentication` | `piv-normal::Piv.auth` uses explicit AES-192 ID 0A, checks exact witness/response TLVs and independently computes AES-192 over the original 00..0F host challenge; retains the native empty 82 response placeholder |
| `test_piv_host_managed_admin_data_objects` | `host_managed_objects` writes original PRINTED/admin bytes, checks unchanged management-record size and successful authentication with the original key, resets, checks public admin/private PRINTED reads and a bounded one-APDU PRINTED read |
| `test_piv_pin_does_not_satisfy_admin` | Same scenario rejects certificate writes before/after PIN verification, checks no certificate record is created, then authenticates the management key and writes successfully |
| `test_delete_certificate_object` | Same scenario writes original 5301AA, checks three-byte backing record, deletes with 5300, checks 6A82 and missing record |

The original mutual-authentication packet exposed two compatibility errors:
AES-192's wire ID is 0A (not 08), and an empty response tag in a mutual proof
must not select external authentication. Rust now preserves both native wire
behaviors; the persistent management key itself remains AES-192 and is not
rewritten. Host and HIL key-rotation helpers use the corrected algorithm ID.
The remaining native management-key install/rotation and old-record migration
cases still require separate audit; these four replacements do not close them.


## Replaced PIV rotation and object-capacity cases

| Legacy case | Executable replacement |
|---|---|
| `test_piv_aes192_management_key` | `piv-normal::management_rotation`: exact default/rotated management metadata, absent 9C key, original new key bytes, FE/FF touch selectors and invalid FD rejection, reset/re-authentication, rejected algorithms 03/08/0C and restored default key |
| `test_piv_retired_cert_lazy_storage` | `object_capacity`: original retired certificate tags 5FC10D/0E/0F/20 start missing, allocate exactly three bytes on PUT, round-trip literal 530155 and delete |
| `test_piv_file_data_object_capacity` | `object_capacity`: all eight original data-object tags accept exactly 3040 bytes; 3041 is rejected without replacing existing data; small first fragments complete PRINTED/IRIS records correctly; certificate boundary additionally checks 6568 accepted and 6569 rejected |
| `test_piv_metadata_bounded_do_storage` | `object_capacity`: PRINTED grows/shrinks through 64/80/30 bytes with exact record sizes, admin data accepts 128 and rejects 129 preserving prior data, original short security/key-history values round-trip |

The native helper's six-/thirteen-block CTZ arithmetic described its LittleFS
layout. The Rust wire quotas remain the same literal 3040/6568 bytes and are
verified through real chained PUT/GET operations. Rust stores each object in its
compact record rather than switching between native attributes and separate
files; exact size, content and shrinkage replace obsolete placement assertions.
Native management-key type migration and invalid-platform-config boot handling
remain pending and are not claimed covered by these replacements.


## Replaced PIV response chaining and unauthenticated queries

| Legacy case | Executable replacement |
|---|---|
| `test_piv_cert_chained_read` | `piv-normal::object_capacity`: original 6564-byte payload pattern, first 200 payload bytes plus selector/TLV then 200-byte PUT fragments; `read_in_chunks` verifies every 256-byte response length, exact 61xx status, complete certificate and exhausted GET RESPONSE rejection |
| `test_piv_get_version_chained_le_absent` | `unauthenticated_queries`: complete three-byte version with absent Le, Le=1/6102 continuation, exact reassembled bytes and exhausted GET RESPONSE; `core-normal::aliased_response_regressions` and `ordinary_response_cleanup_regressions` retain FFI overwrite, zero-progress and abandoned-response coverage |
| `test_piv_get_random_without_authentication` | `unauthenticated_queries`: no PIN authorization before/after queries, 256/32-byte challenges, invalid P1/data rejection, absent-Le default and literal extended Le=257 rejection |
| `test_piv_rsa4096_metadata_chained_read` | `encoding_regressions`: fixed RSA-4096 public-key vector, exact 536-byte metadata with literal prefix/exponent suffix, 256/256/24-byte response chunks and exhausted GET RESPONSE rejection |

The established Rust APDU policy treats absent Le as 256, whereas the native
internal CAPDU fixture represented it as zero. These replacements explicitly
check that policy rather than reintroducing the native zero-Le behavior.
Actual zero-progress output and shared-buffer trailer aliasing remain covered
at the Rust FFI boundary. This batch changes tests only, not production behavior.


## Replaced PIV algorithm configuration cases

| Legacy case | Executable replacement |
|---|---|
| `test_piv_algorithm_extension_read_without_admin` | `piv-normal::algorithm_configuration`: exact ten-byte public configuration and 6982 for an unauthenticated write |
| `test_piv_algorithm_extension_read_after_write` | Same scenario writes the original explicit configuration, resets authorization and reads the exact persistent bytes without management authentication |
| `test_piv_algorithm_extension_rejects_conflicting_ids` | Same scenario rejects the original duplicate ML-KEM/ML-DSA ID, FF Ed25519 ID and reserved P-256 ID with 6A80, checking the complete unchanged configuration after each failure |
| `test_piv_reset_preserves_platform_algorithm_extension` | `reset_and_persistence` writes original custom IDs (Ed25519 22, RSA-4096 51, X25519 52), verifies reset persistence, blocks PIN/PUK and runs real PIV factory reset, then generates Ed25519 through 22 and checks its exact metadata algorithm and matching public key |

The factory-reset regression also retains its existing issuer preservation,
credential deletion and default management/PIN restoration checks. Public
configuration access does not restore authorization; protected writes after
reset are explicitly rejected. No production code changed in this batch.


## Consolidated PIV algorithm and slot correctness coverage

The current test policy retains important behavioral correctness checks rather
than reproducing every native fixture or repeated internal assertion.

| Retired native case | Retained Rust coverage |
|---|---|
| `test_piv_get_metadata_extended_algo_ids` | `piv-normal::classic_keys` checks wire algorithm, policy and generated origin alongside independently verified generated/imported keys; `sm2_operations` checks SM2 wire ID and imported origin alongside independent SM2 verification |
| `test_piv_dynamic_retired_key_slots` | `slots` checks every retired slot is missing before generation, exposes P-256/default PIN metadata afterwards, and is missing after deletion; no separate C filename allocation test |
| `test_ed25519_randomized_streaming` | `randomized_ed25519` independently verifies two long-message signatures, requires distinct signatures and rejects FF signing while extensions are disabled; the duplicated native byte-at-a-time long-message run is removed |
| `test_secp521r1_generate_and_authenticate` | `Piv.generate` checks the exact 140-byte P-521 public response prefix; `classic_keys` independently verifies generation/import signatures and ECDH; native-only nonminimal response wrapper assertions are removed |
| `test_secp521r1_custom_algorithm_id` | `custom_p521` sets 55, generates with explicit PIN/touch policies, checks public encoding and metadata, independently verifies SHA-512 signing through 55, then restores the mapping |

The P-521 generation policy template uses a correct AC length covering both
AA/AB policies. The native fixture's inconsistent outer length is not retained
as a required successful malformed-input behavior. Important malformed-input
rejection and interrupted-operation tests remain separate. Production code and
storage formats are unchanged by this consolidation.


## Container-name authorization and atomic replacement

| Retired native case | Important Rust coverage |
|---|---|
| `test_piv_container_names` | `piv-normal::container_names`: management authorization, valid Unicode including a surrogate pair, invalid UTF-16 and 78/80-byte boundaries, duplicate names across ordinary/F9 slots, reset persistence, idempotent writes, failed rename/clear preserving key and name; `reset_and_persistence` preserves the F9 name through factory reset |
| `test_piv_container_name_replacement` | Same scenario injects a key-generation commit failure and verifies old metadata/name plus an independently verified private operation; a truncated import preserves both, successful import/generation clears the name and the imported key is independently verified |

These use the actual aliased FFI APDU buffer. The host staged-write fixture now
propagates its backing write error instead of falsely returning success. Arming
a one-shot failure before an unchanged-name command also proves that idempotent
writes do not consume a storage write. C attribute layout and duplicate remount
assertions are not replicated; native LittleFS atomic storage tests remain.
The native flash-program failure fixture is still needed by the remaining PQ
name-replacement case, so only unused counters/mount pointers are removed.

**Discrepancy found during the name audit (resolved below):** Rust saved a PQ-generated seed and
cleared the prior name before streaming its public response. Native ML-DSA
replacement commits at response completion and preserves the old key/name if
the response is abandoned. The native PQ aborted-generation/name cases were retained pending the fix below.


## PQ generation commits at public-response completion

| Retired native case | Important Rust coverage |
|---|---|
| `test_piv_mldsa65_aborted_generation_not_installed` | `piv-normal::pq_replacement`: both ML-DSA and ML-KEM new slots remain absent after an interrupted response and reset; rejected extended APDUs invalidate a pending response |
| `test_piv_container_name_mldsa_replacement` | Same scenario partially reads generated public keys, then selects/resets/rejects a command; old key metadata and name survive. Final-commit failure also preserves them; a successful retry publishes matching public metadata and clears the name |

Rust now stages only metadata and seed, initializes the crypto stream from a
wiped bounded seed copy across the shared workspace transition, and commits on
the final response read before success. Cleanup aborts pending staging. Existing
PQ tests independently verify signatures/decapsulation from fully committed
generated keys. The obsolete native flash-program failure wrapper is removed.
This resolves the early-commit discrepancy found in the preceding audit; device
power-loss, runtime stack and physical interoperability acceptance remain open.


## Consolidated PQ seed, generation and configurable algorithm coverage

| Retired native case | Important Rust coverage |
|---|---|
| `test_piv_mldsa65_import_seed_only` | `pq_keys` independently derives the imported public key and verifies signatures; `pq_seed_lifecycle` rejects wrong seed tags, moves the imported key, resets and verifies a signature using the original independent public key |
| `test_piv_mldsa65_generate_metadata_and_sign` | `pq_keys` checks generated origin/algorithm, matching generated and metadata public bytes, 1952-byte public key and compact seed-record size, then independently verifies empty/long-message signatures |
| `test_piv_mlkem768_import_seed_only` | `pq_keys` checks independent seed-derived public bytes and exact implicit rejection; `pq_seed_lifecycle` checks explicit PIN/touch policies, rejects unsupported/duplicate/short seed encodings, preserves old metadata on commit failure and verifies decapsulation after move/reset |
| `test_piv_pq_custom_algorithm_ids` | `pq_seed_lifecycle` uses original 56/57 custom IDs and 80../40.. seed patterns, checks metadata IDs, independently verifies signing/decapsulation, deletes moved keys and restores the mapping |

Native expanded-key/TR structure assertions and deterministic signature
self-comparisons are replaced by independent cryptographic verification and
compact record sizes. No expanded private key is required by the Rust format.
The native ML-KEM lifecycle test remains: its malformed/unauthorized requests
must preserve a pending touch. The current Rust stream entrypoint calls touch
before PIN authorization and before complete GA validation; that ordering needs
its own behavioral regression and review before retiring this case.


## Private-operation authorization precedes touch

`test_piv_mlkem768_generate_metadata_decaps_and_lifecycle` is now retired.
`pq_keys` and `pq_seed_lifecycle` already independently check generation/import,
public metadata, compact storage, decapsulation/implicit rejection and move,
reset and deletion. Its remaining touch-preservation contract is covered by
`key_record_tests::stream_validation_and_pin_precede_touch_and_one_use_grant`:
unauthorized requests never initialize crypto or sample touch; missing and
truncated ciphertext never sample touch or finalize crypto; cancelled presence
retains a PIN_ALWAYS grant; a successful fresh gesture permits one finalization,
and reuse is rejected without another gesture. The classic-signature regression
also rejects an unauthorized request before sampling touch.

Rust now checks authorization at stream admission and waits for touch only after
complete GA validation, consuming the one-use grant after presence succeeds.
Classic signatures likewise check authorization before touch. This resolves the
ordering concern noted in the preceding audit. Error precedence for an input
that is both malformed and unauthorized is not replicated from the native
fixture: admission rejects unauthorized private crypto first. No touch occurs
in either rejection case. Unused native ML-KEM/response collection helpers are
removed; physical gesture/transport compatibility still requires hardware.


## Consolidated PIV malformed-input and stream recovery checks

| Retired native case | Important Rust coverage |
|---|---|
| `test_regression_fuzz` | `piv-normal::malformed_commands`: fixed truncated GA/GET/PUT/GENERATE/IMPORT boundaries, invalid management template/algorithm and successful re-authentication; no fuzz harness, corpus or mutation loop |
| `test_ed25519_general_authenticate_limits` | `interruptions` independently verifies the maximum 544-byte deterministic Ed25519 message and rejects a declared 545-byte message; same-backend signature self-comparison is removed |
| `test_piv_streaming_auth_parser_errors` | `interruptions` rejects a nonempty response tag, inconsistent outer length, truncated template and changed algorithm continuation; independently verifies recovery signatures |
| `test_piv_rejected_apdu_aborts_streaming_auth` | Same scenario interrupts a partially received stream with rejected extended/unsupported-CLA commands, rejects the stale suffix and independently verifies a fresh empty-message signature after each rejection |

The established Rust chain engine waits for a final fragment when CLA still
requests continuation, even if the current TLV is complete. The regression
checks no response data before the empty final fragment and verifies the final
signature. Native immediate rejection of that framing is not replicated.
Redundant malformed combinations and obsolete internal buffer-layout assertions
are omitted; bounds, invalid input, cleanup and recovery remain explicit.


## Retry configuration and default slot policies

| Retired native case | Important Rust coverage |
|---|---|
| `test_set_pin_retries` | `piv-normal::retry_configuration`: management plus PIN authorization, zero/16 invalid limits, unexpected data, distinct PIN/PUK default/retry metadata, wrong-PIN charging, authorization revocation and maximum 15 limits |
| `test_set_pin_retries_failure_invalidates_auth` | Same scenario injects failure into the atomic PIN/PUK record, rejects reuse of both old grants, refuses the uncertain credential cache, and after reset checks the previous durable counters before restoring defaults |
| `test_piv_regular_slot_defaults` | `slots` imports into fresh 9A/9C/9D/9E/82/95 slots, checks exact PIN/touch policies, independently verifies signatures and ECDH for each slot, then deletes test keys |

Rust stores PIN/PUK together in one atomic record, so the former separate-PUK
write-failure fixture is replaced at that transaction boundary. Existing PIN
unit regressions separately cover errors where storage may have committed and
require reloading the actual committed credential. Slot usage is verified by
real operations rather than a native KEY_USAGE_ANY struct field.


## Invalid private-key and peer-point inputs

| Retired native case | Important Rust coverage |
|---|---|
| `test_piv_rsa_sign_rejects_inconsistent_crt_key` | `piv-normal::invalid_private_inputs`: rejects corrupt dp and p=q imports, checks the previous public metadata and independently verifies the surviving key; a host-only record corruption then exercises actual use-time rejection with empty output, followed by restoration and a verified private operation |
| `test_piv_ecdh_rejects_invalid_peer_point` | Same scenario rejects an in-field off-curve P-256 point and a point whose X equals the field modulus, with empty output; valid independently checked signing/ECDH still work afterwards |

The CORRUPT line command belongs only to the in-process test card, not the
firmware or an APDU extension. It changes a bounds-checked byte in the test
storage backend so use-time validation traverses the real Rust loader and
native crypto adapter. No test-only crypto implementation replaces the real
backend. The old purported out-of-field vector had an in-range X; the new
literal modulus boundary actually tests field membership.

## SM2 signature correctness consolidation

Five native SM2 signing cases are replaced by `piv-normal::sm2_operations`,
which drives the Rust APDU engine and independently verifies signatures using
Python curve arithmetic and SM3:

| Retired native case | Important retained coverage |
| --- | --- |
| `test_piv_sm2_stream_sign` | Long, short and empty messages; chained short requests select SM3(Z || message); exact 64-byte raw signatures |
| `test_piv_sm2_stream_sign_custom_id` | Custom identity and maximum 32-byte identity; signatures fail verification with the default identity |
| `test_piv_sm2_digest_mode` | Independent precomputed-digest verification and rejection of a 31-byte digest |
| `test_piv_sm2_stream_tlv_errors` | Misordered, duplicate, empty and oversized identity TLVs reject with 6A80 and empty output; subsequent valid streams succeed |
| `test_piv_sm2_stream_key_mismatch_and_disabled_extension` | P-256 slot and disabled SM2 extension reject stream admission with 6A86 and empty output |

The duplicated byte-at-a-time long-message run and native verifier/helpers are
removed. Malformed identity tests use correctly encoded outer lengths so each
failure exercises its intended semantic rule. No production behavior changed.

## SM2 agreement reference and length coverage

`test_piv_sm2_key_agreement_initiator_reference`,
`test_piv_sm2_key_agreement_length_boundaries` and
`test_piv_sm2_key_agreement_responder_reference` are replaced by the existing
`piv-normal::sm2_operations` scenario. Python independently computes the peer
side for both roles; initiator lengths 16, 32, 125..128 cover the default, custom
identities, and both BER response-length transitions. The responder derives
128 bytes with exact ephemeral-point and response encoding checks. Custom
identities must produce a different key from default identities.

This exposed and fixed a Rust dispatcher bug: the generic rejection of tag 80
prevented SM2 agreement's own-identity parser from being reached. Tag 80 is now
admitted only for SM2 agreement; other private operations retain rejection.
The remaining native agreement lifecycle, malformed-input and PIN-policy cases
still require audit before removal.

## SM2 agreement rejection and interruption coverage

`test_piv_sm2_key_agreement_shape_errors` and
`test_piv_sm2_key_agreement_state_machine` are replaced by
`piv-normal::sm2_operations`. Important rejection checks cover both off-curve
peer points, key lengths 0/129, duplicate/unknown inner tags, a truncated TLV,
missing response tag, own identity bounds, wrong slot algorithm and an empty
slot. Errors must return no data. The truncated inner TLV returns Rust's 6700
length error instead of the native test's 6A80; semantic errors retain 6A80.

Duplicate initiation, changing identity at step 2, signing, PIN verification,
selection and reset must discard the old exchange. A following peer request
must be a responder operation whose derived key matches independent Python
arithmetic. This exposed and fixed a Rust bug retaining initiator state across
SM2 digest signing. The legacy native slot-to-slot roundtrip and PIN-policy
cases remain pending; their interleaving contract is not covered by this removal.

## SM2 interleaved agreement and PIN coverage

The final native SM2 cases, `test_piv_sm2_key_agreement_roundtrip` and
`test_piv_sm2_key_agreement_pin_policy`, now run through
`piv-normal::sm2_operations`. A responder call on slot 9C must preserve the
initiator state on 9A, both keys must agree, and initiation must work again
after completion. This runs under PIN_NEVER and PIN_ONCE (one verification
covers all three operations). PIN_ALWAYS rejects unauthenticated initiation
and response without output; an authenticated responder result is independently
verified and a second operation is rejected because the grant was consumed.

The independent host-role checks retained above complement the two-slot
roundtrip; same-backend agreement alone is not the cryptographic oracle.
Removed all remaining native SM2 fixture helpers and the now-unused chained
request helper. No production code changed in this consolidation.

## PIV attestation algorithms and F9 policy

`test_piv_attestation_f9_policy` is replaced by `piv-normal::attestation`:
authentication is required for F9 generation and certificate writes, P-384
issuer generation/import is rejected, P-256 generation/import has the correct
origin metadata, and moving P-256/P-384 keys into F9 is forbidden.

`test_piv_attestation_all_target_algorithms` is also retired. Rust integration
independently verifies the issuer signature and target public key for all
classical, SM2 and ML-DSA target algorithms covered by that test. SM2 uses the
complete expected SPKI encoding because cryptography does not expose an SM2
public-key object. Missing issuer prerequisites remain covered by the retained
native `test_piv_attestation_certificate`; duplicating its missing-F9 check for
ML-DSA is unnecessary. That remaining case still requires migration of its
prerequisite, certificate-field and persistence checks before removal.

## Final native attestation fixture removal

`test_piv_attestation_certificate` now maps to `piv-normal::attestation` and
`reset_and_persistence`. Missing F9 key/certificate combinations return 6A88
with no response data; an in-process host-only `REMOVE <record>` fixture creates
these states without adding a firmware/APDU command. Independent X.509 parsing
and signature verification checks issuer, copied validity, target subject/SPKI,
exact serial/policy extensions and rejection of imported targets. An explicitly
generated PIN_ALWAYS/TOUCH_CACHED key exercises nondefault policy bytes.
After factory reset, a newly generated key is attested using the preserved F9
key/certificate, with independent verification and public-key matching.

Removed the C certificate fixture, DER walker and native signature-verification
helpers. No production behavior changed; these tests exercise the existing
Rust engine and crypto adapters.

## PIV directory and move/delete correctness

`test_piv_get_metadata_directory` and `test_piv_move_delete_key_extension` are
replaced by `piv-normal::directory_and_move`. Literal wire checks cover sparse
key/certificate flags and policies, empty certificate exclusion and the full
24-slot certificate-only directory in one response. Invalid parameters and
unexpected data are rejected. Move/delete checks require management auth,
reject reserved slots, absent sources, same-slot and occupied destinations;
move across ordinary/retired slots, preserve the source certificate, and delete
the moved key. After reset, the source stays absent and an independently
verified signature proves the original key survived the move. Native key-struct
byte comparisons are removed. No production behavior changed.

## PIV native test executable retired

`test_piv_startup_preserves_state_when_platform_config_is_invalid` is replaced
by `piv-normal::invalid_startup_configuration`. A host-only TRY_RESET command
returns the Rust installation result without aborting the harness. An invalid
stored mapping must fail installation; restoring its byte then permits startup,
with identical key metadata/certificate and an independently verified signature.

`test_piv_migrates_legacy_management_key_types` is retired without recreating
its C enum/storage layout conversion. The documented Rust storage contract
(`piv.md`) does not import legacy C credential files; compact AES-192 management
records and their authentication/rotation are already exercised by
`management_rotation`. This is a storage-format-specific test, not an assertion
that old C credential images are compatible with the Rust firmware.

The `test_piv` executable and its native curve/DER test dependencies are removed
from CMake. The APDU legacy executable remains pending; this does not remove
its shared legacy C applet dependencies or complete the native dependency gate.

## APDU command/response chaining

`test_input_chaining` and `test_output_chaining` are replaced by Rust protocol
coverage. `tlv_value_spans_iso_command_chain_without_reassembly` checks actual
incrementally consumed bytes across a multi-fragment command.
`changed_chain_header_discards_previous_command_and_overflow_recovers` checks
all four header fields, both final/chained replacements, reset of the byte
budget and recovery after overflow. `response_in_two_chunks` additionally
checks the original 512-byte / 254-byte chunk boundary with literal status
words 61FF, 6104 and 9000. Existing response lease tests cover short reads,
cleanup and data wiping. Native chain buffer/internal flag checks are removed;
production code is unchanged.

## Extended Le reaches the applet unchanged

`test_streaming_message_preserves_original_le_for_handler` is replaced by the
actual NDEF registry/engine test in `core/tests/ndef.rs`. The original command
00 B0 00 00 00 04 01 now traverses the Rust engine and must reject a 1025-byte
read from a 1024-byte file with 6700 and no data or pending GET RESPONSE.
The immediately following 1024-byte extended read completes through the real
response source. This complements the existing 300-byte read, proving that Le
is not truncated to the short output buffer before applet validation. Removed
the native callback-only observer; no production code changed.

## HID staged request cleanup

`test_ctaphid_large_rx_session_cleanup` is replaced by `hid-core` and
`usb-sessions`, both driving Rust production transport entrypoints. Existing
sequence-error/timeout checks and new same-channel INIT/transport-reset checks
require wiped scratch release, then successful staged PING reuse. The native
lease fixture asserts every released byte is zero. Real USB integration queues
CCID during partial HID RX, verifies it cannot execute, then checks scratch
release on INIT and CCID recovery after the existing two-second idle ownership
deadline. Unlike the old C owner-enum assertion, scratch release is not treated
as proof that Rust's idle session retention has ended. No production behavior
changed; CCID extended-input and other legacy session cases remain pending.

## Large HID input after CCID ownership

`test_ccid_large_hid_request_survives_session_switch` is replaced by
`usb-sessions`: after CCID selection/authentication, a fragmented clientPIN
getKeyAgreement request with a 700-byte ignored extension completes over real
USB/Rust entrypoints. It requires a successful key-agreement response, wiped
scratch release and revoked CCID authorization on return. This catches cleanup
that runs after new HID bytes have already been staged. The existing `hid-core`
large clientPIN test covers the standalone HID path; duplicated padded GetInfo
runs and C session-owner enum assertions are removed. Production code is
unchanged.

## CCID extended FIDO staging

`test_ccid_extended_fido_request_uses_pke` is replaced by `usb-sessions`.
A real Case 4E clientPIN getKeyAgreement request with a 700-byte extension
crosses USB packets, Rust CCID staging, APDU decoding and crypto. Scratch is
wiped/released while the response remains pending, and the response completes
successfully. USB deconfiguration during partial RX must release scratch;
reconfiguration and power-on permit the full request again. Protocol-level
`ccid.rs` tests additionally cover all split points and reset cleanup. The
native padded GetInfo/abort-helper fixture is removed; no production code changed.

## CCID reentrant request isolation

Removed `test_ccid_rejects_reentrant_command_until_response_finishes` in favor
of assertions in the existing `usb-sessions` integration test. Two distinct
commands arrive before the main loop: the first authenticated query must retain
its sequence and return 9000. While that response is pending, another command
is queued, a further packet is rejected, and competing WebUSB admission cannot
change any response byte. After IN completion, the deferred unsupported command
returns its own sequence and 6D00; the next authenticated query succeeds.

The Rust mailbox deliberately defers one packet rather than reproducing the
legacy C transport's discard-all behavior. The retained correctness contract is
request/response immutability, ordered completion and usable subsequent commands.
Full host CTest passed 28/28 (56.96 seconds).

## CCID slot commands across HID resynchronization

Removed `test_ccid_power_on_does_not_steal_ctaphid_session` and
`test_ccid_slot_status_survives_ctaphid_release`. The existing `usb-sessions`
fixture now submits power-off, power-on and slot-status commands while a real
fragmented HID request owns PKE staging. It checks every staged byte and lease
counter before HID INIT resynchronization, verifies cleanup, and checks each
queued response's family, sequence, length and active/inactive state afterward.

Rust defers CCID dispatch while HID is active; power commands can complete during
the subsequent HID idle lease without resetting HID ownership. The separate
legacy `test_ctaphid_wait_services_only_ccid_presence_poll` remains: servicing
slot polls *during* HID execution is an outstanding compatibility audit, not
established by this replacement. Rust cooperative HID progress currently does
not service the CCID presence mailbox.

Validation: full host CTest passed 28/28 in 66.71 seconds.

## HID execution services CCID presence polls

Closed the progress-path gap identified above and removed
`test_ctaphid_wait_services_only_ccid_presence_poll`. The real `usb-sessions`
fixture injects two CCID slot polls inside a HID selection presence wait. It
checks literal response bytes/sequence, keeps the first IN pending while the
second request arrives, then verifies ordered delivery. A queued power-on
cannot dispatch until HID cancellation unwinds; the CTAP response must remain
KEEPALIVE_CANCEL (2D), after which power-on returns its ATR.

Rust admits only a complete bodyless slot poll in this callback, uses the
existing CCID parser/response buffer, and never resets Core for USB generation
changes or timeouts. Other requests stay queued for ordinary main-loop handling.
No separate workspace or endpoint buffer was added. Physical compatibility and
stack acceptance remain open.

Validation: full host CTest passed 28/28 in 56.93 seconds; the USB-only
composition test also passed after making its excluded HID execution boundary
fail explicitly if accidentally invoked.
