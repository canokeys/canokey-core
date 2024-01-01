// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <device.h>
#include <memzero.h>
#include <oath.h>
#include <pass.h>

#define PASS_FILE "pass"
#define SLOT_SHORT 0
#define SLOT_LONG  1

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

static pass_slot_t slots[2];

int pass_install(const uint8_t reset) {
  if (!reset && get_file_size(PASS_FILE) >= 0) {
    if (read_file(PASS_FILE, slots, 0, sizeof(slots)) < 0) return -1;
    return 0;
  }

  memzero(slots, sizeof(slots));
  if (write_file(PASS_FILE, slots, 0, sizeof(slots), 1) < 0) return -1;

  return 0;
}

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
    // For OATH, the next 4 bytes are oath_offset
    memcpy(&buffer[length], &slot->oath_offset, sizeof(slot->oath_offset));
    length += sizeof(slot->oath_offset);
    buffer[length++] = slot->with_enter;
    break;
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

int pass_write_config(const CAPDU *capdu, RAPDU *rapdu) {
  size_t index = 0;

  for (int i = 0; i < 2; i++) {
    if (index >= LC) {
      // Data is not enough to parse a slot
      EXCEPT(SW_WRONG_LENGTH);
    }

    const slot_type_t type = DATA[index++];
    switch (type) {
    case PASS_SLOT_OFF:
      slots[i].type = type;
      break;

    case PASS_SLOT_STATIC:
      if (DATA[index] > PASS_MAX_PASSWORD_LENGTH) {
        // Password is too long
        EXCEPT(SW_WRONG_DATA);
      }
      slots[i].type = type;
      memcpy(slots[i].password, &DATA[index], DATA[index] + 1);
      index += DATA[index] + 1;
      slots[i].with_enter = DATA[index++];
      break;

    case PASS_SLOT_OATH:
      if (index + sizeof(slots[0].oath_offset) + sizeof(slots[0].with_enter) > LC) {
        // Not enough data for PASS_SLOT_OATH
        EXCEPT(SW_WRONG_DATA);
      }
      slots[i].type = type;
      memcpy(&slots[i].oath_offset, &DATA[index], sizeof(slots[0].oath_offset));
      index += sizeof(slots[0].oath_offset);
      slots[i].with_enter = DATA[index++];
      break;

    default:
      // Invalid slot type
      EXCEPT(SW_WRONG_DATA);
    }
  }

  if (index != LC) {
    // Extra data present that doesn't fit in the slot structure
    EXCEPT(SW_WRONG_LENGTH);
  }

  return write_file(PASS_FILE, slots, 0, sizeof(slots), 1);
}

static int oath_process_offset(uint32_t offset, char *output) {
  uint32_t otp_code;
  int ret = oath_calculate_by_offset(offset, (uint8_t *)&otp_code);
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
    break;
  case PASS_SLOT_STATIC:
    memcpy(output, slot->password + 1, slot->password[0]);
    length = slot->password[0];
    break;
  default:
    return -1;
  }

  if (slot->with_enter) output[length++] = '\r';

  return length;
}
