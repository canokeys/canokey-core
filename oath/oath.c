#include <apdu.h>
#include <fs.h>
#include <hmac.h>
#include <oath.h>
#include <string.h>

#define OATH_FILE "oath"

static enum {
  REMAINING_NONE,
  REMAINING_CALC,
  REMAINING_LIST,
} oath_remaining_type;

static uint8_t challenge[64], challenge_len;

int oath_install(uint8_t reset) {
  oath_remaining_type = REMAINING_NONE;
  create_dir("oath");
  return 0;
}

static int find_record(OATH_RECORD *record) {
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -2;
  uint8_t name_buf[64], name_len;
  name_len = record->name_len;
  if (name_len > 64) return -2;
  memcpy(name_buf, record->name, name_len);
  int nRecords = size / sizeof(OATH_RECORD);
  for (int i = 0; i != nRecords; ++i) {
    size = read_file(OATH_FILE, record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD));
    if (size < 0) return -2;
    if (name_len == record->name_len && memcmp(name_buf, record->name, name_len) == 0) return i;
  }
  return -1;
}

static int add_record(OATH_RECORD *record) {
  int size = get_file_size(OATH_FILE);
  if (size < 0) return -2;
  uint8_t name_len;
  int nRecords = size / sizeof(OATH_RECORD);
  for (int i = 0; i != nRecords; ++i) {
    size = read_file(OATH_FILE, &name_len, i * sizeof(OATH_RECORD), 1);
    if (size < 0) return -2;
    if (name_len == 0) {
      return 0;
    }
  }
  return -1;
}

static int delete_record(uint8_t index) {
  return 0;
}

static const char *build_path(const uint8_t *name, uint8_t len) {
  static char path[70] = "oath/";
  memcpy(path + 5, name, len);
  return path;
}

static int oath_put(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset++];
  if (name_len > 64) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (DATA[offset++] != OATH_TAG_KEY) EXCEPT(SW_WRONG_DATA);
  uint8_t key_len = DATA[offset++];
  if (key_len > 64 + 2) // 2 for algo & digits
    EXCEPT(SW_WRONG_DATA);
  uint8_t alg = DATA[offset];
  if ((alg & OATH_TYPE_MASK) != OATH_TYPE_TOTP ||
      ((alg & OATH_ALG_MASK) != OATH_ALG_SHA1 && (alg & OATH_ALG_MASK) != OATH_ALG_SHA256))
    EXCEPT(SW_WRONG_DATA);
  return write_file(build_path(DATA + 2, name_len), DATA + offset, 0, key_len, 1);
}

static int oath_delete(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  uint8_t offset = 0;
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  uint8_t name_len = DATA[offset];
  if (name_len > 64) EXCEPT(SW_WRONG_DATA);
  int err = remove_file(build_path(DATA + 2, name_len));
  if (err == LFS_ERR_NOENT) EXCEPT(SW_DATA_INVALID);
  return err;
}

static int oath_list(const CAPDU *capdu, RAPDU *rapdu, uint8_t remaining) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  oath_remaining_type = REMAINING_LIST;
  char path[65] = "oath/";
  if (!remaining) open_dir(path);
  uint8_t off = 0, i;
  for (i = 0; i < 3; ++i) {
    RDATA[off] = OATH_TAG_NAME_LIST;
    int err = get_next_filename(path);
    if (err < 0) return -1;
    if (err > 0) break;
    ++off;
    uint8_t len = strlen(path);
    RDATA[off++] = len;
    memcpy(RDATA + off, path, len);
    off += len;
  }
  LL = off;
  if (i == 3)
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
  if (name_len > 64) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
  challenge_len = DATA[offset++];
  if (challenge_len > 64) EXCEPT(SW_WRONG_DATA);
  memcpy(challenge, DATA + offset, challenge_len);
  uint8_t key[66];
  int len = read_file(build_path(DATA + 2, name_len), key, 0, 66);
  if (len == LFS_ERR_NOENT) EXCEPT(SW_DATA_INVALID);
  if (len < 0) return len;

  // to save memory, use name_len to store challenge len,
  // and use key to store hmac result
  if ((key[0] & OATH_ALG_MASK) == OATH_ALG_SHA1) {
    hmac_sha1(key + 2, len - 2, challenge, challenge_len, key);
    name_len = SHA1_DIGEST_LENGTH;
  } else {
    hmac_sha256(key + 2, len - 2, challenge, challenge_len, key);
    name_len = SHA256_DIGEST_LENGTH;
  }

  RDATA[0] = OATH_TAG_RESPONSE;
  RDATA[1] = 5;
  RDATA[2] = key[1];
  offset = key[name_len - 1] & 0xF;
  memcpy(RDATA + 3, key + offset, 4);
  RDATA[3] &= 0x7F;
  LL = 7;
  return 0;
}

static int oath_calculate_all(const CAPDU *capdu, RAPDU *rapdu, uint8_t remaining) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  oath_remaining_type = REMAINING_CALC;
  uint8_t key[66];
  char path[65] = "oath/";
  if (!remaining) {
    uint8_t off_in = 0;
    if (DATA[off_in++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
    challenge_len = DATA[off_in++];
    if (challenge_len > 64) EXCEPT(SW_WRONG_DATA);
    memcpy(challenge, DATA + off_in, challenge_len);
    open_dir(path);
  }
  uint8_t off_out = 0, i;
  for (i = 0; i < 3; ++i) {
    RDATA[off_out] = OATH_TAG_NAME;
    int err = get_next_filename(path);
    if (err < 0) return -1;
    if (err > 0) break;
    ++off_out;
    uint8_t name_len = strlen(path);
    RDATA[off_out++] = name_len;
    memcpy(RDATA + off_out, path, name_len);
    off_out += name_len;
    int key_len = read_file(build_path((uint8_t *)path, name_len), key, 0, 66);
    RDATA[off_out++] = OATH_TAG_RESPONSE;
    RDATA[off_out++] = 5;
    RDATA[off_out++] = key[1];
    if ((key[0] & OATH_ALG_MASK) == OATH_ALG_SHA1) {
      hmac_sha1(key + 2, key_len - 2, challenge, challenge_len, key);
      name_len = SHA1_DIGEST_LENGTH;
    } else {
      hmac_sha256(key + 2, key_len - 2, challenge, challenge_len, key);
      name_len = SHA256_DIGEST_LENGTH;
    }
    uint8_t totp_off = key[name_len - 1] & 0xF;
    memmove(RDATA + off_out, key + totp_off, 4);
    RDATA[off_out] &= 0x7F;
    off_out += 4;
  }
  LL = off_out;
  if (i == 3)
    SW = 0x61FF;
  else
    oath_remaining_type = REMAINING_NONE;
  return 0;
}

static int oath_send_remaining(const CAPDU *capdu, RAPDU *rapdu) {
  if (oath_remaining_type == REMAINING_LIST) return oath_list(capdu, rapdu, 1);
  if (oath_remaining_type == REMAINING_CALC) return oath_calculate_all(capdu, rapdu, 1);
  EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
}

int oath_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  int ret = 0;
  switch (INS) {
  case OATH_INS_PUT:
    ret = oath_put(capdu, rapdu);
    break;
  case OATH_INS_DELETE:
    ret = oath_delete(capdu, rapdu);
    break;
  case OATH_INS_LIST:
    ret = oath_list(capdu, rapdu, 0);
    break;
  case OATH_INS_CALCULATE:
    ret = oath_calculate(capdu, rapdu);
    break;
  case OATH_INS_CALCULATE_ALL:
    ret = oath_calculate_all(capdu, rapdu, 0);
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
