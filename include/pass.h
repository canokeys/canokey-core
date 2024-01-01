/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_PASS_H
#define CANOKEY_CORE_INCLUDE_PASS_H

#include <apdu.h>

#define PASS_MAX_PASSWORD_LENGTH 32

typedef enum {
  PASS_SLOT_OFF,
  PASS_SLOT_OATH,
  PASS_SLOT_STATIC,
} slot_type_t;

typedef struct {
  slot_type_t type;
  union {
    uint8_t password[33]; // 1-byte length + at most 32-byte content
    uint32_t oath_offset;
  };
  uint8_t with_enter;
} __packed pass_slot_t;

int pass_install(uint8_t reset);
int pass_read_config(const CAPDU *capdu, RAPDU *rapdu);
int pass_write_config(const CAPDU *capdu, RAPDU *rapdu);
int pass_handle_touch(uint8_t touch_type, char *output);

#endif // CANOKEY_CORE_INCLUDE_PASS_H
