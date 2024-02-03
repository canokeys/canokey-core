// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <device.h>
#include <memzero.h>
#include <oath.h>
#include <pass.h>

#define PASS_FILE "pass"
#define SLOT_SHORT 0
#define SLOT_LONG  1

typedef struct {
  slot_type_t type;
  union {
    struct {
      uint8_t password_len;
      uint8_t password[PASS_MAX_PASSWORD_LENGTH];
    } __packed;
    struct {
      uint32_t oath_offset;
      uint8_t name_len;
      uint8_t name[MAX_NAME_LEN];
    } __packed;
  };
  uint8_t with_enter;
} __packed pass_slot_t;

static pass_slot_t slots[2];

int pass_install(const uint8_t reset) {
  if (reset || get_file_size(PASS_FILE) != sizeof(slots)) {
    memzero(slots, sizeof(slots));
    if (write_file(PASS_FILE, slots, 0, sizeof(slots), 1) < 0) return -1;
  } else {
    if (read_file(PASS_FILE, slots, 0, sizeof(slots)) < 0) return -1;
  }

  return 0;
}

// Dump slots to buffer, return the length of the buffer
// For each slot, the first byte is the type.
// For PASS_SLOT_OFF, there is no more data
// For PASS_SLOT_STATIC, the second byte is with_enter
// For PASS_SLOT_OATH, the next byte is the length of the name, followed by the name, and the next byte is with_enter
static int dump_slot(const pass_slot_t *slot, uint8_t *buffer) {
  int length = 0;

  // First byte is always the type
  buffer[0] = (uint8_t)slot->type;
  length++;

  switch (slot->type) {
  case PASS_SLOT_OFF:
    break;

  case PASS_SLOT_STATIC:
    // For STATIC, the second byte is with_enter
    buffer[length++] = slot->with_enter;
    break;

  case PASS_SLOT_OATH:
    // For OATH, the second byte is the length of the name
    buffer[length++] = slot->name_len;
    // The next bytes are the name
    memcpy(buffer + length, slot->name, slot->name_len);
    length += slot->name_len;
    // The next byte is with_enter
    buffer[length++] = slot->with_enter;
    break;

  default:
    // ERR_MSG("Invalid type %p %d\n", slot, slot->type);
    return 0;
  }

  return length;
}

int pass_read_config(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);

  int length = dump_slot(&slots[SLOT_SHORT], RDATA);
  length += dump_slot(&slots[SLOT_LONG], RDATA + length);
  LL = length;

  return 0;
}

// P1 for the slot index, 1 for short slot, 2 for long slot
// DATA contains the slot data:
// The first byte is the slot type
// For OFF, there is no more data
// For STATIC, the second byte is the length of the password, followed by the password, and the next byte is with_enter
// OATH is not allowed to be written here
int pass_write_config(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 1 && P1 != 2) EXCEPT(SW_WRONG_P1P2);
  if (LC < 1) EXCEPT(SW_WRONG_LENGTH);

  pass_slot_t *slot = &slots[P1 - 1];

  switch (DATA[0]) {
  case PASS_SLOT_OFF:
    if (LC != 1) EXCEPT(SW_WRONG_LENGTH);
    break;

  case PASS_SLOT_STATIC:
    if (LC < 3) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[1] > PASS_MAX_PASSWORD_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (LC != 3 + DATA[1]) EXCEPT(SW_WRONG_LENGTH);
    slot->password_len = DATA[1];
    memcpy(slot->password, DATA + 2, slot->password_len);
    slot->with_enter = DATA[2 + slot->password_len];
    break;

  default:
    EXCEPT(SW_WRONG_DATA);
  }
  slot->type = (slot_type_t)DATA[0];
  DBG_MSG("Set type %p %d\n", slot, slot->type);

  return write_file(PASS_FILE, slots, 0, sizeof(slots), 1);
}

int pass_update_oath(uint8_t slot_index, uint32_t file_offset, uint8_t name_len, const uint8_t *name, uint8_t with_enter) {
  pass_slot_t *slot = &slots[slot_index];
  slot->type = PASS_SLOT_OATH;
  slot->oath_offset = file_offset;
  slot->name_len = name_len;
  memcpy(slot->name, name, name_len);
  slot->with_enter = with_enter;

  return write_file(PASS_FILE, slots, 0, sizeof(slots), 1);
}

int pass_delete_oath(uint32_t file_offset) {
  if (slots[0].type == PASS_SLOT_OATH && slots[0].oath_offset == file_offset) {
    slots[0].type = PASS_SLOT_OFF;
    return write_file(PASS_FILE, slots, 0, sizeof(slots), 1);
  }
  if (slots[1].type == PASS_SLOT_OATH && slots[1].oath_offset == file_offset) {
    slots[1].type = PASS_SLOT_OFF;
    return write_file(PASS_FILE, slots, 0, sizeof(slots), 1);
  }
  return 0;
}

static int oath_process_offset(uint32_t file_offset, char *output) {
  uint32_t otp_code;
  int ret = oath_calculate_by_offset(file_offset, (uint8_t *)&otp_code);
  if (ret < 0) return ret;
  const int len = ret;

  otp_code = htobe32(otp_code);
  while (ret--) {
    output[ret] = otp_code % 10 + '0';
    otp_code /= 10;
  }
  output[len] = '\0';

  return len;
}

int pass_handle_touch(uint8_t touch_type, char *output) {
  pass_slot_t *slot;
  if (touch_type == TOUCH_SHORT)
    slot = &slots[SLOT_SHORT];
  else if (touch_type == TOUCH_LONG)
    slot = &slots[SLOT_LONG];
  else
    return -1;

  int length;
  switch (slot->type) {
  case PASS_SLOT_OFF:
    return 0;
  case PASS_SLOT_OATH:
    length = oath_process_offset(slot->oath_offset, output);
    if (length < 0) return -1;
    break;
  case PASS_SLOT_STATIC:
    memcpy(output, slot->password, slot->password_len);
    length = slot->password_len;
    break;
  default:
    return -1;
  }

  if (slot->with_enter) output[length++] = '\r';

  return length;
}
