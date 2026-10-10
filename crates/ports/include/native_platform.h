/* SPDX-License-Identifier: Apache-2.0 */
/* Native callback imports for explicit platform fixtures; no Core entrypoints. */
#ifndef CANOKEY_NATIVE_PLATFORM_H
#define CANOKEY_NATIVE_PLATFORM_H
#include <stddef.h>
#include <stdint.h>
#include "port_abi.h"
/* Root-level two-digit hexadecimal filenames, IDs 0..183 (00..b7).
 * IDs 184/185 map to the NDEF-compatible E103/NDEF filenames.
 * Record assignments are defined in crates/ports/src/contracts/storage.rs.
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
int32_t ck_platform_resize(uint8_t file, uint32_t length);
int32_t ck_platform_read_at(uint8_t file, uint32_t offset, uint8_t *output, size_t length);
int32_t ck_platform_write_at(uint8_t file, uint32_t offset, const uint8_t *input, size_t length);
int32_t ck_platform_usage(uint32_t *used, uint32_t *total);
int32_t ck_platform_has_space(uint32_t required, uint32_t reserve);
int32_t ck_platform_mac(uint8_t algorithm, const uint8_t *key, size_t key_length, const uint8_t *input, size_t length,
                        uint8_t output[64]);
int32_t ck_platform_random(uint8_t *output, size_t length);
void ck_platform_serial(uint8_t output[4]);
/* Stable byte ABI, mirrored by StageOperation in crates/ports/src/contracts/storage.rs. */
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
 * All calls are serialized and stage bytes must not be published before commit.
 * Append acknowledgement does not promise durability of unpublished data.
 * The backend may retain a cache lease, released on other storage access,
 * abort/disconnect, or publication. */
int32_t ck_platform_stage(uint8_t operation, uint8_t file, const uint8_t *input, size_t length);
/* Synchronous replacement of unpublished staging, at most eight pieces.
 * Descriptors and bytes are borrowed only until return; commit is separate. */
struct ck_storage_part { const uint8_t *data; size_t length; };
int32_t ck_platform_stage_parts(const struct ck_storage_part *parts, size_t count);
/* ADMIN/PASS input and link-maintenance capabilities. */
void ck_platform_led(uint8_t on);
uint32_t ck_platform_now(void);
uint8_t ck_platform_touched(void);
uint8_t ck_platform_progress(void);
#endif
