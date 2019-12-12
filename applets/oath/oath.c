#include <apdu.h>
#include <fs.h>
#include <hmac.h>
#include <oath.h>
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
  oath_poweroff();
  if (!reset && get_file_size(OATH_FILE) == 0) return 0;
  return write_file(OATH_FILE, NULL, 0, 0, 1);
}

static int oath_put(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t name_offset, key_offset;

  // parse name
  uint8_t offset = 0;
  if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  name_offset = offset;
  offset += name_len;

  // parse key
  if (offset >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_KEY) EXCEPT(SW_WRONG_DATA);
  uint8_t key_len = DATA[offset++];
  if (key_len > MAX_KEY_LEN || key_len <= 2) // 2 for algo & digits
    EXCEPT(SW_WRONG_DATA);
  key_offset = offset;
  uint8_t alg = DATA[offset];
  if (((alg & OATH_TYPE_MASK) != OATH_TYPE_HOTP && (alg & OATH_TYPE_MASK) != OATH_TYPE_TOTP) ||
      ((alg & OATH_ALG_MASK) != OATH_ALG_SHA1 && (alg & OATH_ALG_MASK) != OATH_ALG_SHA256))
    EXCEPT(SW_WRONG_DATA);
  offset += key_len;

  // parse property (optional tag)
  uint8_t prop = 0;
  if (offset < LC && DATA[offset] == OATH_TAG_PROPERTY) {
    offset++;
    prop = DATA[offset++];
    if ((prop & ~(OATH_PROP_INC | OATH_PROP_TOUCH)) != 0) EXCEPT(SW_WRONG_DATA);
  }

  // parse HOTP counter (optional tag)
  uint8_t chal[MAX_CHALLENGE_LEN] = {0};
  if (offset < LC && DATA[offset] == OATH_TAG_COUNTER) {
    offset++;
    if (4 != DATA[offset++]) EXCEPT(SW_WRONG_DATA);
    if ((alg & OATH_TYPE_MASK) != OATH_TYPE_HOTP) EXCEPT(SW_WRONG_DATA);
    memcpy(chal + 4, DATA + offset, 4);
    offset += 4;
  }

  if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

  // find an empty slot to save the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  size_t nRecords = size / sizeof(OATH_RECORD), i;
  OATH_RECORD record;
  for (i = 0; i != nRecords; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == 0) break;
  }
  if (i >= MAX_RECORDS) EXCEPT(SW_NOT_ENOUGH_SPACE);

  record.name_len = name_len;
  memcpy(record.name, DATA + name_offset, name_len);
  record.key_len = key_len;
  memcpy(record.key, DATA + key_offset, key_len);
  record.prop = prop;
  memcpy(record.challenge, chal, MAX_CHALLENGE_LEN);
  return write_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD), 0);
}

static int oath_delete(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);

  // find and delete the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  size_t nRecords = size / sizeof(OATH_RECORD), i;
  OATH_RECORD record;
  for (i = 0; i != nRecords; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, DATA + 2, name_len) == 0) {
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
    if (read_file(OATH_FILE, &record, record_idx++ * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == 0) continue;
    if (off + 2 + record.name_len > LE) {
      SW = 0x61FF;
      break;
    }
    RDATA[off++] = OATH_TAG_NAME_LIST;
    RDATA[off++] = record.name_len;
    memcpy(RDATA + off, record.name, record.name_len);
    off += record.name_len;
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
    if (memcmp(record->challenge, challenge, sizeof(record->challenge)) > 0) return -2;
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

  uint8_t offset = buffer[digest_length - 1] & 0xF;
  return buffer + offset;
}

static int oath_calculate_by_offset(off_t file_offset, uint8_t result[4]) {
  if (file_offset < 0 || file_offset % sizeof(OATH_RECORD) != 0) return -1;
  int size = get_file_size(OATH_FILE);
  if (size < 0 || file_offset >= size) return -1;
  OATH_RECORD record;
  if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;

  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) {
    ERR_MSG("TOTP is not supported");
    return -1;
  } else if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {

    if (oath_increase_counter(&record) < 0) return -1;
    oath_update_challenge_field(&record, file_offset);

    challenge_len = sizeof(record.challenge);
    memcpy(challenge, record.challenge, challenge_len);
  }

  uint8_t hash[SHA256_DIGEST_LENGTH];
  memcpy(result, oath_digest(&record, hash), 4);
  result[3] &= 0x7F;
  return 0;
}

static int oath_set_default(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;

  // find the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  uint32_t nRecords = size / sizeof(OATH_RECORD), i;
  uint32_t file_offset;
  OATH_RECORD record;
  for (i = 0; i != nRecords; ++i) {
    file_offset = i * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, DATA + 2, name_len) == 0) break;
  }
  if (i == nRecords) EXCEPT(SW_DATA_INVALID);

  if (write_attr(OATH_FILE, ATTR_DEFAULT_RECORD, &file_offset, sizeof(file_offset)) < 0) return -1;
  return 0;
}

static int oath_calculate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;

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

  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) {

    if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
    challenge_len = DATA[offset++];
    if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) {
      challenge_len = 0;
      EXCEPT(SW_WRONG_DATA);
    }
    memcpy(challenge, DATA + offset, challenge_len);

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
  RDATA[3] &= 0x7F;
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
    if (DATA[off_in++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
    challenge_len = DATA[off_in++];
    if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) {
      challenge_len = 0;
      EXCEPT(SW_WRONG_DATA);
    }
    memcpy(challenge, DATA + off_in, challenge_len);
  }

  OATH_RECORD record;
  size_t nRecords = size / sizeof(OATH_RECORD), off_out = 0;
  while (off_out < LE) {
    if (record_idx >= nRecords) {
      oath_remaining_type = REMAINING_NONE;
      break;
    }
    size_t file_offset = record_idx++ * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == 0) continue;
    size_t estimated_len = 2 + record.name_len + 2 + 5;
    if (estimated_len + off_out > LE) {
      SW = 0x61FF; // more data available
      break;
    }

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
    RDATA[off_out] &= 0x7F;
    off_out += 4;
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
  uint32_t offset, otp_code;
  if (read_attr(OATH_FILE, ATTR_DEFAULT_RECORD, &offset, sizeof(offset)) < 0) return -1;
  if (oath_calculate_by_offset(offset, (uint8_t *)&otp_code) < 0) return -1;
  snprintf(output, maxlen, "%06d", (int)otp_code % 1000000);
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
