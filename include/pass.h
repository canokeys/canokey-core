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

int pass_install(uint8_t reset);
int pass_read_config(const CAPDU *capdu, RAPDU *rapdu);
int pass_write_config(const CAPDU *capdu, RAPDU *rapdu);
int pass_handle_touch(uint8_t touch_type, char *output);
int pass_update_oath(uint8_t slot_index, uint32_t file_offset, uint8_t name_len, const uint8_t *name, uint8_t with_enter);
int pass_delete_oath(uint32_t file_offset);

#endif // CANOKEY_CORE_INCLUDE_PASS_H
