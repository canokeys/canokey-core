/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_PASS_H
#define CANOKEY_CORE_INCLUDE_PASS_H

#include <apdu.h>

#define PASS_MAX_PASSWORD_LENGTH 32

// YubiKey challenge-response accepts up to a 64-byte challenge and returns
// the raw 20-byte HMAC-SHA1 digest.
#define PASS_HMAC_KEY_LENGTH 20
#define PASS_HMAC_CHALLENGE_LENGTH 64
#define PASS_HMAC_RESPONSE_LENGTH 20

typedef enum {
  PASS_SLOT_OFF,
  PASS_SLOT_OATH,
  PASS_SLOT_STATIC,
  PASS_SLOT_HMACSHA1,
} slot_type_t;

int pass_install(uint8_t reset);
int pass_read_config(const CAPDU *capdu, RAPDU *rapdu);
int pass_write_config(const CAPDU *capdu, RAPDU *rapdu);
int pass_handle_touch(uint8_t touch_type, char *output);
int pass_hmacsha1(uint8_t slot_index, const uint8_t *challenge, uint16_t challenge_len,
                  uint8_t response[PASS_HMAC_RESPONSE_LENGTH]);
int pass_update_oath(uint8_t slot_index, uint32_t file_offset, uint8_t name_len, const uint8_t *name,
                     uint8_t with_enter);
int pass_delete_oath(uint32_t file_offset);

#endif // CANOKEY_CORE_INCLUDE_PASS_H
