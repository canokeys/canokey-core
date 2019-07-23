#ifndef CANOKEY_CORE_OPENPGP_KEY_H
#define CANOKEY_CORE_OPENPGP_KEY_H

#include <stdint.h>

#define KEY_FINGERPRINT_LENGTH 20
#define KEY_DATETIME_LENGTH 4

typedef struct {
  uint8_t e[4];
  uint8_t e_len;
  uint8_t p[128];
  uint8_t p_len;
  uint8_t q[128];
  uint8_t q_len;
} rsa_pri_key_t;

void openpgp_key_get_attributes(void *buf);
int openpgp_key_get_fingerprint(const char *path, void *buf);
int openpgp_key_set_fingerprint(const char *path, const void *buf);
int openpgp_key_get_datetime(const char *path, void *buf);
int openpgp_key_set_datetime(const char *path, const void *buf);
int openpgp_key_get_rsa_pri_key(const char *path, void *buf);
int openpgp_key_set_rsa_pri_key(const char *path, const void *buf);

#endif // CANOKEY_CORE_OPENPGP_KEY_H
