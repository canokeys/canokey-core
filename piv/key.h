#ifndef CANOKEY_CORE_PIV_KEY_H_
#define CANOKEY_CORE_PIV_KEY_H_

#include <stdint.h>

int key_create(const char *path);
int key_read_cert(const char *path, void *buf);
int key_write_cert(const char *path, void *buf, uint16_t len);

#endif // CANOKEY_CORE_PIV_KEY_H_
