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
through the actual APDU engine; the AFL test exercises persistent NDEF updates.

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

## Still requiring individual coverage audit

Six C test executables remain, with 226 registered cases: APDU (96), core
helpers (13), key (25), OATH (18), OpenPGP (16), PIV (58).
Existing Rust suites cover many of these behaviors, but no blanket equivalence
is claimed. Their C applet/protocol dependencies must remain until each case is
mapped to an existing replacement or ported. This ledger is intentionally not
a completion certificate for stage six, production capacity, stack or hardware
interoperability.

The supplemental `virtual-oath-regressions` suite checks OATH counter commit
faults, duplicate records, malformed requests, PASS slots, HMAC, reload and
record-size reuse. It does not yet replace the 18 legacy OATH cases. A truncated
key TLV declaring length FF returns 6700 in the bounded Rust parser, before
semantic validation (legacy C returned 6A80); this parser precedence difference
remains an explicit compatibility item.

Fuzz campaigns, corpus replay and coverage-guided test harnesses are removed.
Literal malformed-input regressions remain correctness tests with explicit
expected results; they do not run mutation campaigns.
