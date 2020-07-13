// SPDX-License-Identifier: Apache-2.0
#include <apdu.h>
#include <device.h>
#include <fs.h>
#include <hmac.h>
#include <inttypes.h>
#include <oath.h>
#include <stdio.h>
#include <string.h>

#define OATH_FILE "oath"
#define MAX_RECORDS 100

static enum {
  REMAINING_NONE,
  REMAINING_CALC,
  REMAINING_LIST,
} oath_remaining_type;

static uint8_t challenge[MAX_CHALLENGE_LEN], challenge_len, record_idx;

void oath_poweroff(void) { oath_remaining_type = REMAINING_NONE; }

int oath_install(uint8_t reset) {
  uint32_t default_item = 0xffffffff;
  oath_poweroff();
  if (!reset && get_file_size(OATH_FILE) >= 0) return 0;
  if (write_file(OATH_FILE, NULL, 0, 0, 1) < 0) return -1;
  return write_attr(OATH_FILE, ATTR_DEFAULT_RECORD, &default_item, sizeof(default_item));
}

static int oath_put(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t name_offset, key_offset;

  // parse name
  uint8_t offset = 0;
  if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  name_offset = offset;
  offset += name_len;

  // parse key
  if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_KEY) EXCEPT(SW_WRONG_DATA);
  if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
  uint8_t key_len = DATA[offset++];
  if (key_len > MAX_KEY_LEN || key_len <= 2) // 2 for algo & digits
    EXCEPT(SW_WRONG_DATA);
  key_offset = offset;
  if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
  uint8_t alg = DATA[offset];
  if (((alg & OATH_TYPE_MASK) != OATH_TYPE_HOTP && (alg & OATH_TYPE_MASK) != OATH_TYPE_TOTP) ||
      ((alg & OATH_ALG_MASK) != OATH_ALG_SHA1 && (alg & OATH_ALG_MASK) != OATH_ALG_SHA256))
    EXCEPT(SW_WRONG_DATA);
  uint8_t digits = DATA[offset + 1];
  if (digits < 4 || digits > 8) EXCEPT(SW_WRONG_DATA);
  offset += key_len;

  // parse property (optional tag)
  uint8_t prop = 0;
  if (offset < LC && DATA[offset] == OATH_TAG_PROPERTY) {
    offset++;
    if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (1 != DATA[offset++]) EXCEPT(SW_WRONG_DATA);
    if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
    prop = DATA[offset++];
    if ((prop & ~OATH_PROP_ALL_FLAGS) != 0) EXCEPT(SW_WRONG_DATA);
  }

  // parse HOTP counter (optional tag)
  uint8_t chal[MAX_CHALLENGE_LEN] = {0};
  if (offset < LC && DATA[offset] == OATH_TAG_COUNTER) {
    offset++;
    if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (4 != DATA[offset++]) EXCEPT(SW_WRONG_DATA);
    if ((alg & OATH_TYPE_MASK) != OATH_TYPE_HOTP) EXCEPT(SW_WRONG_DATA);
    if (offset + 4 > LC) EXCEPT(SW_WRONG_LENGTH);
    memcpy(chal + 4, DATA + offset, 4);
    offset += 4;
  }

  if (offset > LC) EXCEPT(SW_WRONG_LENGTH);
  // else if (offset < LC) EXCEPT(SW_WRONG_DATA);

  // find an empty slot to save the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  size_t nRecords = size / sizeof(OATH_RECORD), unoccupied;
  OATH_RECORD record;
  unoccupied = nRecords; // append by default
  for (size_t i = 0; i != nRecords; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    // duplicated name found
    if (record.name_len == name_len && memcmp(record.name, DATA + name_offset, name_len) == 0) {
      DBG_MSG("dup name\n");
      EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    }
    // empty slot found
    if (record.name_len == 0 && unoccupied == nRecords) unoccupied = i;
  }
  // DBG_MSG("unoccupied=%zu nRecords=%zu\n", unoccupied, nRecords);
  if (unoccupied == nRecords && // empty slot not found
      unoccupied >= MAX_RECORDS // number of records exceeded the limit
  )
    EXCEPT(SW_NOT_ENOUGH_SPACE);

  record.name_len = name_len;
  memcpy(record.name, DATA + name_offset, name_len);
  record.key_len = key_len;
  memcpy(record.key, DATA + key_offset, key_len);
  record.prop = prop;
  memcpy(record.challenge, chal, MAX_CHALLENGE_LEN);
  return write_file(OATH_FILE, &record, unoccupied * sizeof(OATH_RECORD), sizeof(OATH_RECORD), 0);
}

static int oath_delete(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  uint8_t *name_ptr = &DATA[offset];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

  // find and delete the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  size_t nRecords = size / sizeof(OATH_RECORD);
  OATH_RECORD record;
  for (size_t i = 0; i != nRecords; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, name_ptr, name_len) == 0) {
      record.name_len = 0;
      return write_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD), 0);
    }
  }
  EXCEPT(SW_DATA_INVALID);
}

static int oath_list(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  oath_remaining_type = REMAINING_LIST;
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  OATH_RECORD record;
  size_t nRecords = size / sizeof(OATH_RECORD), off = 0;

  while (off < LE) {
    if (record_idx >= nRecords) {
      oath_remaining_type = REMAINING_NONE;
      break;
    }
    if (read_file(OATH_FILE, &record, record_idx * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (off + 2 + record.name_len + 4 > LE) {
      // shouldn't increase the record_idx in this case
      SW = 0x61FF;
      break;
    }
    record_idx++;
    if (record.name_len == 0) continue;

    RDATA[off++] = OATH_TAG_NAME;
    RDATA[off++] = record.name_len;
    memcpy(RDATA + off, record.name, record.name_len);
    off += record.name_len;
    RDATA[off++] = OATH_TAG_META;
    RDATA[off++] = 2;
    RDATA[off++] = record.key[0];
    RDATA[off++] = record.key[1];
  }
  LL = off;

  return 0;
}

static int oath_update_challenge_field(OATH_RECORD *record, size_t file_offset) {
  return write_file(OATH_FILE, record->challenge, file_offset + (size_t) & ((OATH_RECORD *)0)->challenge,
                    sizeof(record->challenge), 0);
}

static int oath_enforce_increasing(OATH_RECORD *record, size_t file_offset) {
  if ((record->prop & OATH_PROP_INC)) {
    if (challenge_len != sizeof(record->challenge)) return -1;
    // DBG_MSG("challenge_len=%u %hhu %hhu\n", challenge_len, record->challenge[7], challenge[7]);
    if (memcmp(record->challenge, challenge, sizeof(record->challenge)) > 0) return -2;
    memcpy(record->challenge, challenge, sizeof(record->challenge));
    oath_update_challenge_field(record, file_offset);
    return 0;
  }
  return 0;
}

static int oath_increase_counter(OATH_RECORD *record) {
  int i;
  for (i = sizeof(record->challenge) - 1; i >= 0; i--) {
    record->challenge[i]++;
    if (record->challenge[i] != 0) break;
  }
  return i >= 0 ? 0 : -1;
}

static uint8_t *oath_digest(OATH_RECORD *record, uint8_t buffer[SHA256_DIGEST_LENGTH]) {
  uint8_t digest_length;
  if ((record->key[0] & OATH_ALG_MASK) == OATH_ALG_SHA1) {
    hmac_sha1(record->key + 2, record->key_len - 2, challenge, challenge_len, buffer);
    digest_length = SHA1_DIGEST_LENGTH;
  } else {
    hmac_sha256(record->key + 2, record->key_len - 2, challenge, challenge_len, buffer);
    digest_length = SHA256_DIGEST_LENGTH;
  }
  // print_hex(buffer, digest_length);

  uint8_t offset = buffer[digest_length - 1] & 0xF;
  buffer[offset] &= 0x7F;
  return buffer + offset;
}

static int oath_calculate_by_offset(size_t file_offset, uint8_t result[4]) {
  if (file_offset % sizeof(OATH_RECORD) != 0) return -2;
  int size = get_file_size(OATH_FILE);
  if (size < 0 || file_offset >= size) return -2;
  OATH_RECORD record;
  if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;

  if (record.name_len == 0) {
    ERR_MSG("Record deleted\n");
    return -2;
  }
  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) {
    ERR_MSG("TOTP is not supported\n");
    return -1;
  }
  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
    if (oath_increase_counter(&record) < 0) return -1;
    oath_update_challenge_field(&record, file_offset);

    challenge_len = sizeof(record.challenge);
    memcpy(challenge, record.challenge, challenge_len);
    // print_hex(challenge, challenge_len);
  }

  uint8_t hash[SHA256_DIGEST_LENGTH];
  memcpy(result, oath_digest(&record, hash), 4);
  // print_hex(result, 4);
  return 0;
}

static int oath_set_default(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  uint8_t *name_ptr = &DATA[offset];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

  // find the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  uint32_t nRecords = size / sizeof(OATH_RECORD), i;
  uint32_t file_offset;
  OATH_RECORD record;
  for (i = 0; i != nRecords; ++i) {
    file_offset = i * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, name_ptr, name_len) == 0) break;
  }
  if (i == nRecords) EXCEPT(SW_DATA_INVALID);
  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);

  if (write_attr(OATH_FILE, ATTR_DEFAULT_RECORD, &file_offset, sizeof(file_offset)) < 0) return -1;
  return 0;
}

static int oath_calculate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

  // find the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  size_t nRecords = size / sizeof(OATH_RECORD), i;
  size_t file_offset;
  OATH_RECORD record;
  for (i = 0; i != nRecords; ++i) {
    file_offset = i * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, DATA + 2, name_len) == 0) break;
  }
  if (i == nRecords) EXCEPT(SW_DATA_INVALID);

#ifndef TEST
  if ((record.prop & OATH_PROP_TOUCH)) {
    if (!is_nfc()) {
      start_blinking(2);
      if (get_touch_result() == TOUCH_NO) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
      set_touch_result(TOUCH_NO);
      stop_blinking();
    }
  }
#endif

  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) {
    if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
    challenge_len = DATA[offset++];
    if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) {
      challenge_len = 0;
      EXCEPT(SW_WRONG_DATA);
    }
    if (offset + challenge_len > LC) EXCEPT(SW_WRONG_LENGTH);
    memcpy(challenge, DATA + offset, challenge_len);
    offset += challenge_len;
    if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

    if (oath_enforce_increasing(&record, file_offset) < 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

  } else if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {

    if (oath_increase_counter(&record) < 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    oath_update_challenge_field(&record, file_offset);

    challenge_len = sizeof(record.challenge);
    memcpy(challenge, record.challenge, challenge_len);
  }

  RDATA[0] = OATH_TAG_RESPONSE;
  RDATA[1] = 5;
  RDATA[2] = record.key[1];

  uint8_t hash[SHA256_DIGEST_LENGTH];
  memcpy(RDATA + 3, oath_digest(&record, hash), 4);
  LL = 7;
  return 0;
}

static int oath_calculate_all(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  oath_remaining_type = REMAINING_CALC;
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;

  // store challenge in the first call
  if (record_idx == 0) {
    uint8_t off_in = 0;
    if (off_in + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[off_in++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
    challenge_len = DATA[off_in++];
    if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) {
      challenge_len = 0;
      EXCEPT(SW_WRONG_DATA);
    }
    if (off_in + challenge_len > LC) EXCEPT(SW_WRONG_LENGTH);
    memcpy(challenge, DATA + off_in, challenge_len);
    off_in += challenge_len;
    if (off_in > LC) EXCEPT(SW_WRONG_LENGTH);
  }

  OATH_RECORD record;
  size_t nRecords = size / sizeof(OATH_RECORD), off_out = 0;
  while (off_out < LE) {
    if (record_idx >= nRecords) {
      oath_remaining_type = REMAINING_NONE;
      break;
    }
    size_t file_offset = record_idx * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    size_t estimated_len = 2 + record.name_len + 2 + 5;
    if (estimated_len + off_out > LE) {
      // shouldn't increase the record_idx in this case
      SW = 0x61FF; // more data available
      break;
    }
    record_idx++;
    if (record.name_len == 0) continue;

    RDATA[off_out++] = OATH_TAG_NAME;
    RDATA[off_out++] = record.name_len;
    memcpy(RDATA + off_out, record.name, record.name_len);
    off_out += record.name_len;

    if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
      RDATA[off_out++] = OATH_TAG_NO_RESP;
      RDATA[off_out++] = 1;
      RDATA[off_out++] = record.key[1];
      continue;
    }
    if ((record.prop & OATH_PROP_TOUCH)) {
      RDATA[off_out++] = OATH_TAG_REQ_TOUCH;
      RDATA[off_out++] = 1;
      RDATA[off_out++] = record.key[1];
      continue;
    }

    if (oath_enforce_increasing(&record, file_offset) < 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    RDATA[off_out++] = OATH_TAG_RESPONSE;
    RDATA[off_out++] = 5;
    RDATA[off_out++] = record.key[1];

    uint8_t hash[SHA256_DIGEST_LENGTH];
    memmove(RDATA + off_out, oath_digest(&record, hash), 4);
    off_out += 4;
  }
  LL = off_out;

  return 0;
}

int oath_export(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  size_t record_idx = P2;
  if (P1 != 0x00 || P2 >= MAX_RECORDS) EXCEPT(SW_WRONG_P1P2);
  if (LE < 3) EXCEPT(SW_UNABLE_TO_PROCESS);
  size_t free_length = LE - 3; // reserve space for OATH_TAG_NEXT_IDX

  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;

  OATH_RECORD record;
  size_t nRecords = size / sizeof(OATH_RECORD), off_out = 0;
  for (; record_idx < nRecords; record_idx++) {
    size_t file_offset = record_idx * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    // skip empty or non-exportable slots
    if (!record.name_len || !(record.prop & OATH_PROP_EXPORTABLE)) continue;

    size_t record_len = 2 + record.name_len + 2 + record.key_len + 3 + 2 + MAX_CHALLENGE_LEN;
    if (record_len > free_length) {
      SW = 0x61FF; // more data available
      RDATA[off_out++] = OATH_TAG_NEXT_IDX;
      RDATA[off_out++] = 1;
      RDATA[off_out++] = record_idx;
      break;
    }

    // length: 2 + record.name_len
    RDATA[off_out++] = OATH_TAG_NAME;
    RDATA[off_out++] = record.name_len;
    memcpy(RDATA + off_out, record.name, record.name_len);
    off_out += record.name_len;

    // length: 2 + record.key_len
    RDATA[off_out++] = OATH_TAG_KEY;
    RDATA[off_out++] = record.key_len;
    memcpy(RDATA + off_out, record.key, record.key_len);
    off_out += record.key_len;

    // length: 3
    RDATA[off_out++] = OATH_TAG_PROPERTY;
    RDATA[off_out++] = 1;
    RDATA[off_out++] = record.prop;

    // length: 2 + MAX_CHALLENGE_LEN
    RDATA[off_out++] = OATH_TAG_CHALLENGE;
    RDATA[off_out++] = MAX_CHALLENGE_LEN;
    memcpy(RDATA + off_out, record.challenge, MAX_CHALLENGE_LEN);
    off_out += MAX_CHALLENGE_LEN;

    free_length -= record_len;
  }
  LL = off_out;
  return 0;
}

static int oath_send_remaining(const CAPDU *capdu, RAPDU *rapdu) {
  if (oath_remaining_type == REMAINING_LIST) return oath_list(capdu, rapdu);
  if (oath_remaining_type == REMAINING_CALC) return oath_calculate_all(capdu, rapdu);
  EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
}

int oath_process_one_touch(char *output, size_t maxlen) {
  uint32_t offset = 0xffffffff, otp_code;
  if (read_attr(OATH_FILE, ATTR_DEFAULT_RECORD, &offset, sizeof(offset)) < 0) return -2;
  int ret = oath_calculate_by_offset(offset, (uint8_t *)&otp_code);
  if (ret < 0) return ret;
  otp_code = htobe32(otp_code);
  snprintf(output, maxlen, "%06" PRIu32, otp_code % 1000000);
  return 0;
}

int oath_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  int ret = 0;
  switch (INS) {
  case OATH_INS_SELECT:
    if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    break;
  case OATH_INS_PUT:
    ret = oath_put(capdu, rapdu);
    break;
  case OATH_INS_DELETE:
    ret = oath_delete(capdu, rapdu);
    break;
  case OATH_INS_LIST:
    record_idx = 0;
    ret = oath_list(capdu, rapdu);
    break;
  case OATH_INS_CALCULATE:
    ret = oath_calculate(capdu, rapdu);
    break;
  case OATH_INS_SET_DEFAULT:
    ret = oath_set_default(capdu, rapdu);
    break;
  case OATH_INS_CALCULATE_ALL:
    record_idx = 0;
    ret = oath_calculate_all(capdu, rapdu);
    break;
  case OATH_INS_SEND_REMAINING:
    ret = oath_send_remaining(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
