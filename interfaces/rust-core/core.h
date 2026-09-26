/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_RUST_CORE_H
#define CANOKEY_RUST_CORE_H
#include <stddef.h>
#include <stdint.h>
/* Main-loop only: serialize every call, including touch and reset. Callbacks
 * must never reenter the core. Buffers are borrowed only until return.
 * exchange supports identical input/output buffers; capacity includes SW.
 * Reset releases transport ownership and authorization, not stored slots. */
void CCID_Loop(void);
void WebUSB_Loop(void);
uint8_t ck_transport_progress(void);
#if ENABLE_IFACE_CTAPHID
uint8_t CTAPHID_Loop(uint8_t wait_for_user);
#endif
/* HID calls are main-loop-only. poll requires distinct 64-byte buffers and
 * completion of the previous IN report. See the Rust ABI for result bits. */
#if ENABLE_IFACE_CTAPHID
void ck_hid_reset(void);
uint8_t ck_hid_poll(const uint8_t *input, uint32_t received, uint32_t now, uint8_t *output);
uint8_t ck_hid_busy(void);
uint8_t ck_hid_active(void);
/* Serialized Rust transport callbacks; never reenter applet state or use PKE. */
void ck_hid_execution_begin(uint32_t cid);
void ck_hid_execution_end(void);
uint8_t ck_hid_executing(void);
uint8_t ck_hid_progress(void);
void ck_hid_keepalive(uint8_t waiting);
uint8_t ck_ccid_idle(void);
uint8_t ck_ccid_scratch_busy(void);
/* Mirrors ctap::MAX_REQUEST. Only the CBOR body occupies PKE. */
#define CK_CTAP_MAX_REQUEST 1024u
#endif
int32_t ck_core_install(void);
void ck_core_reset(void);
uint8_t ck_core_applet_count(void);
int32_t ck_core_exchange(uint8_t owner, const uint8_t *input, size_t length, uint8_t *output, size_t capacity);
/* Present only when PASS is enabled. Slot indices here are zero based. */
int32_t ck_core_output_sample(uint8_t pressed, uint32_t now, uint8_t ready);
int32_t ck_core_touch(uint8_t slot, uint8_t *output, size_t capacity);
int32_t ck_core_challenge(uint8_t slot, const uint8_t *input, size_t length, uint8_t output[20]);
/* Root-level two-digit hexadecimal filenames, IDs 0..183 (00..b7).
 * Record assignments are defined in rust/core/src/ports/storage.rs.
 * File 0 = versioned slots, file 1 = versioned PIN,
 * file 2 = OATH metadata, file 3 = OATH records.
 * Files 4..13 are OpenPGP state, PW1/PW3/RC, SIG/DEC/AUT keys and certificates.
 * read returns -1 only for missing, other negative values for errors.
 * read/write return exact byte counts, negative on failure.
 * A successful write must be durable and atomic. Crypto must complete or halt;
 * callbacks must not return an uninitialized digest on hardware failure. */
int32_t ck_platform_read(uint8_t file, uint8_t *output, size_t length);
int32_t ck_platform_write(uint8_t file, const uint8_t *input, size_t length);
void ck_platform_hmac_sha1(const uint8_t key[20], const uint8_t *input, size_t length, uint8_t output[20]);
/* OATH capabilities. read_at/write_at return exact byte counts; write_at
 * atomically replaces the region while retaining other bytes. size returns
 * -1 for missing. has_space returns 1/0, or a negative error. MAC algorithms
 * 1/2/3 are SHA-1/256/512; mac/random return 0 on success. progress may send
 * transport keepalive but must never reenter Rust; 0 cancels presence wait. */
int32_t ck_platform_size(uint8_t file);
int32_t ck_platform_read_at(uint8_t file, uint32_t offset, uint8_t *output, size_t length);
int32_t ck_platform_write_at(uint8_t file, uint32_t offset, const uint8_t *input, size_t length);
int32_t ck_platform_has_space(uint32_t required, uint32_t reserve);
int32_t ck_platform_mac(uint8_t algorithm, const uint8_t *key, size_t key_length, const uint8_t *input, size_t length,
                        uint8_t output[64]);
int32_t ck_platform_random(uint8_t *output, size_t length);
void ck_platform_serial(uint8_t output[4]);
/* Stable byte ABI, mirrored by StageOperation in rust/ffi/src/platform/storage.rs. */
enum ck_stage_operation {
  CK_STAGE_BEGIN = 0,
  CK_STAGE_APPEND = 1,
  CK_STAGE_PUBLISH = 2,
  CK_STAGE_ABORT = 3,
  CK_STAGE_REMOVE = 4,
  CK_STAGE_RENAME = 5,
};
enum ck_mac_algorithm { CK_MAC_SHA1 = 1, CK_MAC_SHA256 = 2, CK_MAC_SHA512 = 3 };
/* One staged-object transaction, separate from atomic record-update staging.
 * Operations: 0 begin, 1 append, 2 publish to file, 3 abort, 4 remove file,
 * 5 rename file to the one-byte destination ID in input (length = 1).
 * Remove takes length = 0 and succeeds for missing files. Returns 0 on success.
 * All calls are serialized and stage bytes must not be published before commit. */
int32_t ck_platform_stage(uint8_t operation, uint8_t file, const uint8_t *input, size_t length);
/* ADMIN/PASS input and link-maintenance capabilities. */
void ck_platform_led(uint8_t on);
uint32_t ck_platform_now(void);
uint8_t ck_platform_touched(void);
uint8_t ck_platform_progress(void);
// Transport-only progress; must not reenter the Rust core from a callback.
uint8_t ck_ccid_progress(void);
// Main-loop raw touch sampling for non-blocking CTAP1 presence.
void ck_core_presence_sample(void);
#endif
