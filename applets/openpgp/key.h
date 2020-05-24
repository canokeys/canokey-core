#ifndef CANOKEY_CORE_OPENPGP_KEY_H
#define CANOKEY_CORE_OPENPGP_KEY_H

#include <stdint.h>

#define KEY_FINGERPRINT_LENGTH 20
#define KEY_DATETIME_LENGTH 4
#define MAX_ATTR_LENGTH 13

int openpgp_key_get_attributes(const char *path, void *buf);
int openpgp_key_set_attributes(const char *path, const void *buf, uint8_t len);
int openpgp_key_get_fingerprint(const char *path, void *buf);
int openpgp_key_set_fingerprint(const char *path, const void *buf);
int openpgp_key_get_datetime(const char *path, void *buf);
int openpgp_key_set_datetime(const char *path, const void *buf);
int openpgp_key_get_status(const char *path);
int openpgp_key_set_status(const char *path, uint8_t status);
int openpgp_key_get_key(const char *path, void *buf, uint16_t len);
int openpgp_key_set_key(const char *path, const void *buf, uint16_t len);

#endif // CANOKEY_CORE_OPENPGP_KEY_H
