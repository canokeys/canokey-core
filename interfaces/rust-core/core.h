/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_RUST_CORE_H
#define CANOKEY_RUST_CORE_H
#include <stddef.h>
#include <stdint.h>
/* Main-loop only: serialize every call, including touch and reset. Callbacks
 * must never reenter the core. Buffers are borrowed only until return.
 * exchange supports identical input/output buffers; capacity includes SW.
 * Reset releases transport ownership and authorization, not stored slots. */
int32_t ck_core_install(void);
void ck_core_reset(void);
uint8_t ck_core_applet_count(void);
int32_t ck_core_exchange(uint8_t owner, const uint8_t *input, size_t length, uint8_t *output, size_t capacity);
/* Present only when PASS is enabled. Slot indices here are zero based. */
int32_t ck_core_output_sample(uint8_t pressed, uint32_t now, uint8_t ready);
int32_t ck_core_touch(uint8_t slot, uint8_t *output, size_t capacity);
int32_t ck_core_challenge(uint8_t slot, const uint8_t *input, size_t length, uint8_t output[20]);
/* New /rust namespace: file 0 = versioned slots, file 1 = versioned PIN,
 * file 2 = OATH metadata, file 3 = OATH records.
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
/* ADMIN/PASS input and link-maintenance capabilities. */
void ck_platform_led(uint8_t on);
uint32_t ck_platform_now(void);
uint8_t ck_platform_touched(void);
uint8_t ck_platform_progress(void);
#endif
