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
int32_t ck_core_touch(uint8_t slot, uint8_t *output, size_t capacity);
int32_t ck_core_challenge(uint8_t slot, const uint8_t *input, size_t length, uint8_t output[20]);
/* PASS platform hooks: file 0 = slots, file 1 = prototype PIN record.
 * size returns -1 for missing, other negative values for errors.
 * read/write return exact byte counts, negative on failure.
 * A successful write must be durable and atomic. Crypto must complete or halt;
 * callbacks must not return an uninitialized digest on hardware failure. */
int32_t ck_platform_size(uint8_t file);
int32_t ck_platform_read(uint8_t file, uint8_t *output, size_t length);
int32_t ck_platform_write(uint8_t file, const uint8_t *input, size_t length);
void ck_platform_sha256(const uint8_t *input, size_t length, uint8_t output[32]);
void ck_platform_hmac_sha1(const uint8_t key[20], const uint8_t *input, size_t length, uint8_t output[20]);
#endif
