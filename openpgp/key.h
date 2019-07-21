#ifndef CANOKEY_CORE_OPENPGP_KEY_H
#define CANOKEY_CORE_OPENPGP_KEY_H

#include <stdint.h>

#define FINGERPRINT_LENGTH 20
#define DATETIME_LENGTH 4

void openpgp_key_get_attributes(uint8_t *buf);
int openpgp_key_get_fingerprint(const char *path, uint8_t *buf);
int openpgp_key_set_fingerprint(const char *path, uint8_t *buf);
int openpgp_key_get_datetime(const char *path, uint8_t *buf);
int openpgp_key_set_datetime(const char *path, uint8_t *buf);

#endif // CANOKEY_CORE_OPENPGP_KEY_H
