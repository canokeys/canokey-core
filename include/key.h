#ifndef CANOKEY_CORE_KEY_H
#define CANOKEY_CORE_KEY_H

#include <algo.h>
#include <ecc.h>
#include <rsa.h>
#include <stdbool.h>

#define KEY_ERR_LENGTH (-1)
#define KEY_ERR_DATA (-2)
#define KEY_ERR_PROC (-3)

typedef enum {
  SIGN = 0x01,
  ENCRYPT = 0x02,
  KEY_AGREEMENT = 0x04,
} key_usage_t;

typedef enum {
  KEY_ORIGIN_NOT_PRESENT = 0x00,
  KEY_ORIGIN_GENERATED = 0x01,
  KEY_ORIGIN_IMPORTED = 0x02,
} key_origin_t;

typedef enum {
  PIN_POLICY_NEVER = 0x01,
  PIN_POLICY_ONCE = 0x02,
  PIN_POLICY_ALWAYS = 0x03,
} pin_policy_t;

typedef enum {
  TOUCH_POLICY_DEFAULT = 0x00,   // disabled in both OpenPGP and PIV
  TOUCH_POLICY_NEVER = 0x01,     // not used in OpenPGP; the same as default in PIV
  TOUCH_POLICY_ALWAYS = 0x02,    // not used in OpenPGP; enabled in PIV without cache
  TOUCH_POLICY_CACHED = 0x03,    // enabled in OpenPGP; enabled in PIV with cache
  TOUCH_POLICY_PERMANENT = 0x04, // permanently enabled in OpenPGP; not used in PIV
} touch_policy_t;

typedef struct {
  key_type_t type;
  key_origin_t origin;
  key_usage_t usage;
  pin_policy_t pin_policy;
  touch_policy_t touch_policy;
} key_meta_t;

typedef struct {
  key_meta_t meta;
  union {
    rsa_key_t rsa;
    ecc_key_t ecc;
    uint8_t data[0];
  };
} ck_key_t;

/**
 * Shared key buffer for OpenPGP/PIV operations.
 * Safe to share because only one APDU is processed at a time (single-threaded).
 * MUST be zeroed with memzero() after each use.
 */
extern ck_key_t key_buffer;

/**
 * Encode public key
 *
 * @param key            key type
 * @param buf            buffer
 * @param include_length encode the length or not
 * @return encoded length
 */
int ck_encode_public_key(ck_key_t *key, uint8_t *buf, bool include_length);

/**
 * Parse the key imported to PIV
 *
 * @param key     parsed key. origin will be set to KEY_ORIGIN_IMPORTED.
 * @param buf     data buffer that contains the key
 * @param buf_len data buffer length
 * @return 0 for success. Negative values for errors.
 */
int ck_parse_piv(ck_key_t *key, const uint8_t *buf, size_t buf_len);

int ck_parse_piv_policies(ck_key_t *key, const uint8_t *buf, size_t buf_len);

int ck_parse_openpgp(ck_key_t *key, const uint8_t *buf, size_t buf_len);

int ck_read_key_metadata(const char *path, key_meta_t *meta);

int ck_write_key_metadata(const char *path, const key_meta_t *meta);

int ck_read_key(const char *path, ck_key_t *key);

int ck_write_key(const char *path, const ck_key_t *key);

int ck_generate_key(ck_key_t *key);

int ck_sign(const ck_key_t *key, const uint8_t *input, size_t input_len, uint8_t *sig);

/**
 * Streaming key import state for RSA keys.
 * Allows receiving key data across multiple chain blocks without buffering
 * the entire key in the chaining buffer.
 *
 * Usage:
 *   1. Call ck_parse_openpgp_stream_init / ck_parse_piv_stream_init with the first block
 *      (must contain complete TLV headers). Returns header_consumed bytes.
 *   2. Call ck_key_stream_feed with subsequent data until all component data is received.
 *   3. Call ck_key_stream_finalize to validate and return the result.
 */
typedef struct {
  bool active;
  uint8_t n_components;    // Number of components (6 for OpenPGP RSA, 5 for PIV RSA)
  uint8_t current_comp;    // Current component being received
  uint16_t comp_len[6];    // Length of each component
  uint16_t comp_received;  // Bytes received for current component
  uint8_t *comp_dest[6];   // Destination pointers into key_buffer
  uint16_t comp_offset[6]; // Write offset within destination (for right-alignment)
  uint16_t total_data;     // Total data bytes expected
  uint16_t total_received; // Total data bytes received
} ck_key_stream_t;

extern ck_key_stream_t key_stream;

/**
 * Initialize streaming parse for OpenPGP RSA key import.
 * Parses TLV headers from buf and prepares streaming state.
 * @return offset to first data byte (header bytes consumed), or negative error.
 */
int ck_parse_openpgp_stream_init(ck_key_t *key, const uint8_t *buf, size_t buf_len);

/**
 * Initialize streaming parse for PIV RSA key import.
 * @return offset to first data byte (header bytes consumed), or negative error.
 */
int ck_parse_piv_stream_init(ck_key_t *key, const uint8_t *buf, size_t buf_len);

/**
 * Feed data to the streaming key import.
 * @return 0 on success, negative on error.
 */
int ck_key_stream_feed(ck_key_t *key, const uint8_t *data, size_t len);

/**
 * Finalize streaming key import. Validates key data.
 * @return 0 on success, negative error code on failure.
 */
int ck_key_stream_finalize(ck_key_t *key);

/**
 * Abort streaming key import.
 */
void ck_key_stream_abort(void);

#endif // CANOKEY_CORE_KEY_H
