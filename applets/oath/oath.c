// SPDX-License-Identifier: Apache-2.0
#include <apdu.h>
#include <crypto-util.h>
#include <device.h>
#include <fs.h>
#include <hmac.h>
#include <memzero.h>
#include <oath.h>
#include <pass.h>
#include <rand.h>
#include <string.h>

#define OATH_FILE "oath"
#define MAX_RECORDS 100

static enum {
  REMAINING_NONE,
  REMAINING_CALC_FULL,
  REMAINING_CALC_TRUNC,
  REMAINING_LIST,
} oath_remaining_type;

static uint8_t auth_challenge[MAX_CHALLENGE_LEN], record_idx, is_validated;

void oath_poweroff(void) {
  oath_remaining_type = REMAINING_NONE;
  is_validated = false;
}

int oath_install(const uint8_t reset) {
  oath_poweroff();
  if (!reset && get_file_size(OATH_FILE) >= 0) return 0;
  if (write_file(OATH_FILE, NULL, 0, 0, 1) < 0) return -1;
  if (write_attr(OATH_FILE, ATTR_KEY, NULL, 0) < 0) return -1;
  uint8_t handle[HANDLE_LEN];
  random_buffer(handle, sizeof(handle));
  if (write_attr(OATH_FILE, ATTR_HANDLE, handle, sizeof(handle)) < 0) return -1;
  return 0;
}

static int oath_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  memcpy(RDATA, ((uint8_t[]){OATH_TAG_VERSION, 3, 0x06, 0x00, 0x00, OATH_TAG_NAME, HANDLE_LEN}), 7);
  if (read_attr(OATH_FILE, ATTR_HANDLE, RDATA + 7, HANDLE_LEN) < 0) return -1;
  LL = 7 + HANDLE_LEN;

  // check if there is a key
  uint8_t dummy;
  const int32_t ret = read_attr(OATH_FILE, ATTR_KEY, &dummy, 1);
  if (ret < 0) return -1;

  if (ret == 0) { // no key is set
    is_validated = true;
  } else {
    random_buffer(auth_challenge, sizeof(auth_challenge));
    RDATA[7 + HANDLE_LEN] = OATH_TAG_CHALLENGE;
    RDATA[8 + HANDLE_LEN] = sizeof(auth_challenge);
    memcpy(RDATA + 9 + HANDLE_LEN, auth_challenge, sizeof(auth_challenge));
    RDATA[9 + HANDLE_LEN + sizeof(auth_challenge)] = OATH_TAG_ALGORITHM;
    RDATA[10 + HANDLE_LEN + sizeof(auth_challenge)] = 1;
    RDATA[11 + HANDLE_LEN + sizeof(auth_challenge)] = OATH_ALG_SHA1;
    LL += 5 + sizeof(auth_challenge);
  }

  return 0;
}

static int oath_put(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  // parse name
  uint16_t offset = 0;
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  const uint8_t name_len = DATA[offset++];
  const uint8_t *name_ptr = &DATA[offset];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;

  // parse key
  if (LC <= offset + 4) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_KEY) EXCEPT(SW_WRONG_DATA);
  const uint8_t key_len = DATA[offset++];
  const uint8_t *key_ptr = &DATA[offset];
  if (key_len > MAX_KEY_LEN || key_len <= 2) // 2 for algo & digits
    EXCEPT(SW_WRONG_DATA);
  const uint8_t alg = DATA[offset];
  if ((alg & OATH_TYPE_MASK) != OATH_TYPE_HOTP && (alg & OATH_TYPE_MASK) != OATH_TYPE_TOTP) EXCEPT(SW_WRONG_DATA);
  if ((alg & OATH_ALG_MASK) != OATH_ALG_SHA1 && (alg & OATH_ALG_MASK) != OATH_ALG_SHA256 &&
      (alg & OATH_ALG_MASK) != OATH_ALG_SHA512)
    EXCEPT(SW_WRONG_DATA);
  const uint8_t digits = DATA[offset + 1];
  if (digits < 4 || digits > 8) EXCEPT(SW_WRONG_DATA);
  offset += key_len;

  // parse property (optional tag)
  uint8_t prop = 0;
  if (LC > offset && DATA[offset] == OATH_TAG_PROPERTY) {
    if (LC <= ++offset) EXCEPT(SW_WRONG_LENGTH);
    prop = DATA[offset++];
    if ((prop & ~OATH_PROP_ALL_FLAGS) != 0) EXCEPT(SW_WRONG_DATA);
  }

  // parse HOTP counter (optional tag)
  uint8_t chal[MAX_CHALLENGE_LEN] = {0};
  if (offset < LC && DATA[offset] == OATH_TAG_COUNTER) {
    if (LC <= ++offset) EXCEPT(SW_WRONG_LENGTH);
    if (4 != DATA[offset++]) EXCEPT(SW_WRONG_DATA);
    if ((alg & OATH_TYPE_MASK) != OATH_TYPE_HOTP) EXCEPT(SW_WRONG_DATA);
    if (LC < offset + 4) EXCEPT(SW_WRONG_LENGTH);
    memcpy(chal + 4, DATA + offset, 4);
    offset += 4;
  }

  if (LC != offset) EXCEPT(SW_WRONG_LENGTH);

  // find an empty slot to save the record
  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  const size_t n_records = size / sizeof(OATH_RECORD);
  OATH_RECORD record;
  size_t unoccupied = n_records; // append by default
  for (size_t i = 0; i != n_records; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    // duplicated name found
    if (record.name_len == name_len && memcmp(record.name, name_ptr, name_len) == 0) {
      DBG_MSG("dup name\n");
      EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    }
    // empty slot found
    if (record.name_len == 0 && unoccupied == n_records) unoccupied = i;
  }
  DBG_MSG("unoccupied=%zu n_records=%zu\n", unoccupied, n_records);
  if (unoccupied == n_records &&  // empty slot not found
      unoccupied >= MAX_RECORDS) // number of records exceeded the limit
    EXCEPT(SW_NOT_ENOUGH_SPACE);

  record.name_len = name_len;
  memcpy(record.name, name_ptr, name_len);
  record.key_len = key_len;
  memcpy(record.key, key_ptr, key_len);
  record.prop = prop;
  memcpy(record.challenge, chal, MAX_CHALLENGE_LEN);
  return write_file(OATH_FILE, &record, unoccupied * sizeof(OATH_RECORD), sizeof(OATH_RECORD), 0);
}

static int oath_delete(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint16_t offset = 0;
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  const uint8_t name_len = DATA[offset++];
  const uint8_t *name_ptr = &DATA[offset];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (LC < offset) EXCEPT(SW_WRONG_LENGTH);

  // find and delete the record
  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  const size_t n_records = size / sizeof(OATH_RECORD);
  OATH_RECORD record;
  for (size_t i = 0; i != n_records; ++i) {
    if (read_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, name_ptr, name_len) == 0) {
      if (pass_delete_oath(i * sizeof(OATH_RECORD)) < 0) return -1;
      record.name_len = 0;
      return write_file(OATH_FILE, &record, i * sizeof(OATH_RECORD), sizeof(OATH_RECORD), 0);
    }
  }
  EXCEPT(SW_DATA_INVALID);
}

static int oath_rename(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  uint16_t offset = 0;
  if (LC <= 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  const uint8_t old_name_len = DATA[offset++];
  const uint8_t *old_name_ptr = &DATA[offset];
  if (old_name_len > MAX_NAME_LEN || old_name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += old_name_len;
  if (LC <= offset + 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  const uint8_t new_name_len = DATA[offset++];
  const uint8_t *new_name_ptr = &DATA[offset];
  if (new_name_len > MAX_NAME_LEN || new_name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += new_name_len;
  if (LC < offset) EXCEPT(SW_WRONG_LENGTH);

  // find the record
  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  const uint32_t n_records = size / sizeof(OATH_RECORD);
  uint32_t i, idx_old;
  OATH_RECORD record;
  for (i = 0, idx_old = n_records; i < n_records; ++i) {
    const uint32_t file_offset = i * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (idx_old == n_records && record.name_len == old_name_len && memcmp(record.name, old_name_ptr, old_name_len) == 0) idx_old = i;
    if (record.name_len == new_name_len && memcmp(record.name, new_name_ptr, new_name_len) == 0) {
      DBG_MSG("dup name\n");
      EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    }
  }
  if (idx_old == n_records) EXCEPT(SW_DATA_INVALID);

  // update the name
  if (read_file(OATH_FILE, &record, idx_old * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
  record.name_len = new_name_len;
  memcpy(record.name, new_name_ptr, new_name_len);
  return write_file(OATH_FILE, &record, idx_old * sizeof(OATH_RECORD), sizeof(OATH_RECORD), 0);
}

static int oath_set_code(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  // check input data first
  uint16_t offset = 0;
  if (LC == 0) goto clear_code;
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_KEY) EXCEPT(SW_WRONG_DATA);
  const uint8_t key_len = DATA[offset++];
  const uint8_t *key_ptr = &DATA[offset];
  if (key_len == 0) { // clear the code
clear_code:
    is_validated = 1;
    return write_attr(OATH_FILE, ATTR_KEY, NULL, 0);
  }
  if (key_len != KEY_LEN + 1) EXCEPT(SW_WRONG_DATA);
  offset += key_len;
  if (LC <= offset + 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
  const uint8_t chal_len = DATA[offset++];
  const uint8_t *chal_ptr = &DATA[offset];
  offset += chal_len;
  if (LC <= offset + 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_FULL_RESPONSE) EXCEPT(SW_WRONG_DATA);
  const uint8_t resp_len = DATA[offset++];
  const uint8_t *resp_ptr = &DATA[offset];
  if (resp_len != SHA1_DIGEST_LENGTH) EXCEPT(SW_WRONG_DATA);
  offset += resp_len;
  if (LC != offset) EXCEPT(SW_WRONG_LENGTH);

  // verify the response
  uint8_t hmac[SHA1_DIGEST_LENGTH];
  hmac_sha1(key_ptr + 1, KEY_LEN, chal_ptr, chal_len, hmac);
  if (memcmp_s(hmac, resp_ptr, SHA1_DIGEST_LENGTH) != 0) EXCEPT(SW_DATA_INVALID);

  is_validated = 0;
  // save the key
  return write_attr(OATH_FILE, ATTR_KEY, key_ptr + 1, key_len - 1);
}

static int oath_validate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  // check input data first
  uint16_t offset = 0;
  if (LC <= 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_FULL_RESPONSE) EXCEPT(SW_WRONG_DATA);
  const uint8_t resp_len = DATA[offset++];
  const uint8_t *resp_ptr = &DATA[offset];
  if (resp_len != SHA1_DIGEST_LENGTH) EXCEPT(SW_WRONG_DATA);
  offset += resp_len;
  if (LC <= offset + 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
  const uint8_t chal_len = DATA[offset++];
  const uint8_t *chal_ptr = &DATA[offset];
  offset += chal_len;
  if (LC != offset) EXCEPT(SW_WRONG_LENGTH);

  // verify the response
  uint8_t key[KEY_LEN];
  const int32_t ret = read_attr(OATH_FILE, ATTR_KEY, key, KEY_LEN);
  if (ret < 0) return -1;
  if (ret == 0) EXCEPT(SW_DATA_INVALID);
  uint8_t hmac[SHA1_DIGEST_LENGTH];
  hmac_sha1(key, KEY_LEN, auth_challenge, sizeof(auth_challenge), hmac);
  is_validated = memcmp_s(hmac, resp_ptr, SHA1_DIGEST_LENGTH) == 0;
  if (!is_validated) EXCEPT(SW_WRONG_DATA);

  // build the response
  hmac_sha1(key, KEY_LEN, chal_ptr, chal_len, hmac);
  memzero(key, KEY_LEN);
  RDATA[0] = OATH_TAG_FULL_RESPONSE;
  RDATA[1] = SHA1_DIGEST_LENGTH;
  memcpy(RDATA + 2, hmac, SHA1_DIGEST_LENGTH);
  LL = SHA1_DIGEST_LENGTH + 2;

  return 0;
}

static int oath_list(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  oath_remaining_type = REMAINING_LIST;
  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  OATH_RECORD record;
  const size_t n_records = size / sizeof(OATH_RECORD);
  size_t off = 0;

  while (record_idx < n_records) {
    if (read_file(OATH_FILE, &record, record_idx * sizeof(OATH_RECORD), sizeof(OATH_RECORD)) < 0) return -1;
    if (off + 3 + record.name_len > LE) { // tag (1) + name_len (1) + algo (1) + name
      // shouldn't increase the record_idx in this case
      SW = 0x61FF;
      break;
    }
    record_idx++;
    if (record.name_len == 0) continue;

    RDATA[off++] = OATH_TAG_NAME_LIST;
    RDATA[off++] = record.name_len + 1;
    RDATA[off++] = record.key[0];
    memcpy(RDATA + off, record.name, record.name_len);
    off += record.name_len;
  }
  if (record_idx >= n_records) {
    oath_remaining_type = REMAINING_NONE;
  }
  LL = off;

  return 0;
}

static int oath_update_challenge_field(const OATH_RECORD *record, const size_t file_offset) {
  return write_file(OATH_FILE, record->challenge, file_offset + (size_t) & ((OATH_RECORD *)0)->challenge,
                    sizeof(record->challenge), 0);
}

static int oath_enforce_increasing(OATH_RECORD *record, const size_t file_offset, const uint8_t challenge_len, uint8_t challenge[MAX_CHALLENGE_LEN]) {
  if (record->prop & OATH_PROP_INC) {
    if (challenge_len != sizeof(record->challenge)) return -1;
    DBG_MSG("challenge_len=%u %hhu %hhu\n", challenge_len, record->challenge[7], challenge[7]);
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

static uint8_t *oath_digest(const OATH_RECORD *record, uint8_t buffer[SHA512_DIGEST_LENGTH],
                            const uint8_t challenge_len, uint8_t challenge[MAX_CHALLENGE_LEN], const bool truncated) {
  uint8_t digest_length;
  if ((record->key[0] & OATH_ALG_MASK) == OATH_ALG_SHA1) {
    hmac_sha1(record->key + 2, record->key_len - 2, challenge, challenge_len, buffer);
    digest_length = SHA1_DIGEST_LENGTH;
  } else if ((record->key[0] & OATH_ALG_MASK) == OATH_ALG_SHA256) {
    hmac_sha256(record->key + 2, record->key_len - 2, challenge, challenge_len, buffer);
    digest_length = SHA256_DIGEST_LENGTH;
  } else {
    hmac_sha512(record->key + 2, record->key_len - 2, challenge, challenge_len, buffer);
    digest_length = SHA512_DIGEST_LENGTH;
  }
  if (!truncated) {
    return (uint8_t *)(uintptr_t)digest_length;
  }

  const uint8_t offset = buffer[digest_length - 1] & 0xF;
  buffer[offset] &= 0x7F;
  return buffer + offset;
}

int oath_calculate_by_offset(size_t file_offset, uint8_t result[4]) {
  if (file_offset % sizeof(OATH_RECORD) != 0) return -2;
  const int size = get_file_size(OATH_FILE);
  if (size < 0 || file_offset >= (size_t)size) return -2;
  uint8_t challenge_len;
  uint8_t challenge[MAX_CHALLENGE_LEN];
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
  } else {
    return -1;
  }

  uint8_t hash[SHA512_DIGEST_LENGTH];
  memcpy(result, oath_digest(&record, hash, challenge_len, challenge, true), 4);
  return record.key[1]; // the number of digits
}

static int oath_set_default(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x01 && P1 != 0x02) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x00 && P2 != 0x01) EXCEPT(SW_WRONG_P1P2);

  uint16_t offset = 0;
  if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  const uint8_t name_len = DATA[offset++];
  const uint8_t *name_ptr = &DATA[offset];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

  // find the record
  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  const uint32_t n_records = size / sizeof(OATH_RECORD);
  uint32_t i;
  uint32_t file_offset = 0;
  OATH_RECORD record;
  for (i = 0; i != n_records; ++i) {
    file_offset = i * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, name_ptr, name_len) == 0) break;
  }
  if (i == n_records) EXCEPT(SW_DATA_INVALID);
  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);

  return pass_update_oath(P1 -1, file_offset, record.name_len, record.name, P2);
}

static int oath_calculate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || (P2 != 0x00 && P2 != 0x01)) EXCEPT(SW_WRONG_P1P2);

  uint16_t offset = 0;
  if (LC <= 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[offset++] != OATH_TAG_NAME) EXCEPT(SW_WRONG_DATA);
  const uint8_t name_len = DATA[offset++];
  if (name_len > MAX_NAME_LEN || name_len == 0) EXCEPT(SW_WRONG_DATA);
  offset += name_len;
  if (LC < offset) EXCEPT(SW_WRONG_LENGTH);

  // find the record
  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;
  const size_t n_records = size / sizeof(OATH_RECORD);
  size_t i;
  size_t file_offset = 0;
  OATH_RECORD record;
  for (i = 0; i != n_records; ++i) {
    file_offset = i * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    if (record.name_len == name_len && memcmp(record.name, DATA + 2, name_len) == 0) break;
  }
  if (i == n_records) EXCEPT(SW_DATA_INVALID);

  if (record.prop & OATH_PROP_TOUCH) {
    if (!is_nfc()) {
      switch (wait_for_user_presence(WAIT_ENTRY_CCID)) {
      case USER_PRESENCE_CANCEL:
      case USER_PRESENCE_TIMEOUT:
        EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
      default: // USER_PRESENCE_OK
        break;
      }
    }
  }

  uint8_t challenge_len;
  uint8_t challenge[MAX_CHALLENGE_LEN];
  if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_TOTP) {
    if (offset + 1 >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[offset++] != OATH_TAG_CHALLENGE) EXCEPT(SW_WRONG_DATA);
    challenge_len = DATA[offset++];
    if (challenge_len > MAX_CHALLENGE_LEN || challenge_len == 0) {
      EXCEPT(SW_WRONG_DATA);
    }
    if (offset + challenge_len > LC) EXCEPT(SW_WRONG_LENGTH);
    memcpy(challenge, DATA + offset, challenge_len);
    offset += challenge_len;
    if (offset > LC) EXCEPT(SW_WRONG_LENGTH);

    if (oath_enforce_increasing(&record, file_offset, challenge_len, challenge) < 0)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  } else if ((record.key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
    if (oath_increase_counter(&record) < 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    oath_update_challenge_field(&record, file_offset);

    challenge_len = sizeof(record.challenge);
    memcpy(challenge, record.challenge, challenge_len);
  } else {
    return -1;
  }

  if (P2) {
    RDATA[0] = OATH_TAG_RESPONSE;
    RDATA[1] = 5;

    uint8_t hash[SHA512_DIGEST_LENGTH];
    memcpy(RDATA + 3, oath_digest(&record, hash, challenge_len, challenge, true), 4);
  } else {
    RDATA[0] = OATH_TAG_FULL_RESPONSE;
    RDATA[1] = 1 + (uint8_t)(uintptr_t)oath_digest(&record, &RDATA[3], challenge_len, challenge, false);
  }
  RDATA[2] = record.key[1];
  LL = RDATA[1] + 2;

  return 0;
}

static int oath_calculate_all(const CAPDU *capdu, RAPDU *rapdu) {
  static uint8_t challenge_len;
  static uint8_t challenge[MAX_CHALLENGE_LEN];

  if (P2 != 0x00 && P2 != 0x01) EXCEPT(SW_WRONG_P1P2);

  const int size = get_file_size(OATH_FILE);
  if (size < 0) return -1;

  // store challenge in the first call
  if (record_idx == 0) {
    uint16_t off_in = 0;
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
    oath_remaining_type = P2 ? REMAINING_CALC_TRUNC : REMAINING_CALC_FULL;
  }

  OATH_RECORD record;
  const size_t n_records = size / sizeof(OATH_RECORD);
  size_t off_out = 0;
  while (record_idx < n_records) {
    const size_t file_offset = record_idx * sizeof(OATH_RECORD);
    if (read_file(OATH_FILE, &record, file_offset, sizeof(OATH_RECORD)) < 0) return -1;
    const size_t estimated_len = 2 + record.name_len + 2 + 1 + (oath_remaining_type == REMAINING_CALC_TRUNC ? 4 : SHA512_DIGEST_LENGTH);
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
    if (record.prop & OATH_PROP_TOUCH) {
      RDATA[off_out++] = OATH_TAG_REQ_TOUCH;
      RDATA[off_out++] = 1;
      RDATA[off_out++] = record.key[1];
      continue;
    }

    if (oath_enforce_increasing(&record, file_offset, challenge_len, challenge) < 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    if (oath_remaining_type == REMAINING_CALC_TRUNC) {
      RDATA[off_out++] = OATH_TAG_RESPONSE;
      RDATA[off_out++] = 5;
      RDATA[off_out++] = record.key[1];

      uint8_t hash[SHA512_DIGEST_LENGTH];
      memcpy(RDATA + off_out, oath_digest(&record, hash, challenge_len, challenge, true), 4);
      off_out += 4;
    } else {
      uint8_t *hash = &RDATA[off_out + 3];
      RDATA[off_out++] = OATH_TAG_FULL_RESPONSE;
      RDATA[off_out++] = 1 + (uint8_t)(uintptr_t)oath_digest(&record, hash, challenge_len, challenge, false);
      RDATA[off_out] = record.key[1];
      off_out += RDATA[off_out - 1];
    }
  }
  if (record_idx >= n_records) {
    oath_remaining_type = REMAINING_NONE;
  }
  LL = off_out;

  return 0;
}

static int oath_send_remaining(const CAPDU *capdu, RAPDU *rapdu) {
  if (oath_remaining_type == REMAINING_LIST) return oath_list(capdu, rapdu);
  if (oath_remaining_type == REMAINING_CALC_FULL || oath_remaining_type == REMAINING_CALC_TRUNC) return oath_calculate_all(capdu, rapdu);
  EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
}

// ReSharper disable once CppDFAConstantFunctionResult
int oath_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  if (!is_validated && INS != OATH_INS_SELECT && INS != OATH_INS_VALIDATE) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

  int ret;
  switch (INS) {
  case OATH_INS_PUT:
    ret = oath_put(capdu, rapdu);
    break;
  case OATH_INS_DELETE:
    ret = oath_delete(capdu, rapdu);
    break;
  case OATH_INS_SET_CODE:
    ret = oath_set_code(capdu, rapdu);
    break;
  case OATH_INS_RENAME:
    ret = oath_rename(capdu, rapdu);
    break;
  case OATH_INS_LIST:
    record_idx = 0;
    ret = oath_list(capdu, rapdu);
    break;
  case OATH_INS_CALCULATE:
    ret = oath_calculate(capdu, rapdu);
    break;
  case OATH_INS_VALIDATE:
    ret = oath_validate(capdu, rapdu);
    break;
  case OATH_INS_SELECT:
    if (P1 == 0x04) {
      ret = oath_select(capdu, rapdu);
    } else if (P1 == 0x00) {
      if (!is_validated) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
      record_idx = 0;
      ret = oath_calculate_all(capdu, rapdu);
    } else {
      EXCEPT(SW_WRONG_P1P2);
    }
    break;
  case OATH_INS_SEND_REMAINING:
    ret = oath_send_remaining(capdu, rapdu);
    break;
  case OATH_INS_SET_DEFAULT:
    ret = oath_set_default(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
