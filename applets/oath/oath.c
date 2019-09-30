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

void oath_poweroff(void) {
  oath_remaining_type = REMAINING_NONE;
}

int oath_install(uint8_t reset) {
  oath_poweroff();
  if (!reset && get_file_size(OATH_FILE) == 0) return 0;
  return write_file(OATH_FILE, NULL, 0, 0, 1);
}

static int oath_put(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  // parse name
  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;

  // parse key
  if (DATA[offset++] != OATH_TAG_KEY) EXCEPT(SW_WRONG_DATA);
  uint8_t key_len = DATA[offset++];
  if (key_len > MAX_KEY_LEN || key_len <= 2) // 2 for algo & digits
    EXCEPT(SW_WRONG_DATA);
  uint8_t alg = DATA[offset];
  if ((alg & OATH_TYPE_MASK) != OATH_TYPE_TOTP ||
      ((alg & OATH_ALG_MASK) != OATH_ALG_SHA1 && (alg & OATH_ALG_MASK) != OATH_ALG_SHA256))
    EXCEPT(SW_WRONG_DATA);

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
  memcpy(record.name, DATA + 2, name_len);
  record.key_len = key_len;
  memcpy(record.key, DATA + offset, key_len);
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
  size_t nRecords = size / sizeof(OATH_RECORD), off = 0, i;

  for (i = 0; i < 8; ++i) {
    if (record_idx >= nRecords) break;
    if (read_file(OATH_FILE, &record, record_idx++ * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == 0) continue;
    RDATA[off++] = OATH_TAG_NAME_LIST;
    RDATA[off++] = record.name_len;
    memcpy(RDATA + off, record.name, record.name_len);
    off += record.name_len;
  }
  LL = off;

  if (i == 8)
    SW = 0x61FF;
  else
    oath_remaining_type = REMAINING_NONE;
  return 0;
}

static int oath_calculate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;

  if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
  challenge_len = DATA[offset++];
  if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) EXCEPT(SW_WRONG_DATA);
  memcpy(challenge, DATA + offset, challenge_len);

  // find the record
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  size_t nRecords = size / sizeof(OATH_RECORD), i;
  OATH_RECORD record;
  for (i = 0; i != nRecords; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, DATA + 2, name_len) == 0) break;
  }
  if (i == nRecords) EXCEPT(SW_DATA_INVALID);

  RDATA[0] = OATH_TAG_RESPONSE;
  RDATA[1] = 5;
  RDATA[2] = record.key[1];

  // use record.key to store hmac result
  uint8_t digest_length;
  if ((record.key[0] & OATH_ALG_MASK) == OATH_ALG_SHA1) {
    hmac_sha1(record.key + 2, record.key_len - 2, challenge, challenge_len, record.key);
    digest_length = SHA1_DIGEST_LENGTH;
  } else {
    hmac_sha256(record.key + 2, record.key_len - 2, challenge, challenge_len, record.key);
    digest_length = SHA256_DIGEST_LENGTH;
  }

  offset = record.key[digest_length - 1] & 0xF;
  memcpy(RDATA + 3, record.key + offset, 4);
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
    if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) EXCEPT(SW_WRONG_DATA);
    memcpy(challenge, DATA + off_in, challenge_len);
  }

  OATH_RECORD record;
  size_t nRecords = size / sizeof(OATH_RECORD), off_out = 0, i;
  for (i = 0; i < 8; ++i) {
    if (record_idx >= nRecords) break;
    if (read_file(OATH_FILE, &record, record_idx++ * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == 0) continue;
    RDATA[off_out++] = OATH_TAG_NAME;
    RDATA[off_out++] = record.name_len;
    memcpy(RDATA + off_out, record.name, record.name_len);
    off_out += record.name_len;
    RDATA[off_out++] = OATH_TAG_RESPONSE;
    RDATA[off_out++] = 5;
    RDATA[off_out++] = record.key[1];

    uint8_t digest_length;
    if ((record.key[0] & OATH_ALG_MASK) == OATH_ALG_SHA1) {
      hmac_sha1(record.key + 2, record.key_len - 2, challenge, challenge_len, record.key);
      digest_length = SHA1_DIGEST_LENGTH;
    } else {
      hmac_sha256(record.key + 2, record.key_len - 2, challenge, challenge_len, record.key);
      digest_length = SHA256_DIGEST_LENGTH;
    }
    uint8_t totp_off = record.key[digest_length - 1] & 0xF;
    memmove(RDATA + off_out, record.key + totp_off, 4);
    RDATA[off_out] &= 0x7F;
    off_out += 4;
  }
  LL = off_out;

  if (i == 8)
    SW = 0x61FF;
  else
    oath_remaining_type = REMAINING_NONE;
  return 0;
}

static int oath_send_remaining(const CAPDU *capdu, RAPDU *rapdu) {
  if (oath_remaining_type == REMAINING_LIST) return oath_list(capdu, rapdu);
  if (oath_remaining_type == REMAINING_CALC) return oath_calculate_all(capdu, rapdu);
  EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
}

int oath_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  int ret = 0;
  switch (INS) {
  case OATH_INS_SELECT:
    // Do nothing
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
