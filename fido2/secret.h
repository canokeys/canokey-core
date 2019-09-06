#ifndef CANOKEY_CORE_FIDO2_SECRET_H_
#define CANOKEY_CORE_FIDO2_SECRET_H_

#include <ctap.h>

int get_sign_counter(uint32_t *counter);
int increase_counter(uint32_t *counter);
int generate_key_handle(KeyHandle *kh, uint8_t *pubkey);
size_t sign_with_device_key(const uint8_t *digest, uint8_t *sig);
size_t sign_with_private_key(const uint8_t *key, const uint8_t *digest, uint8_t *sig);
int verify_key_handle(KeyHandle *kh);
int get_cert(uint8_t *buf);

#endif // CANOKEY_CORE_FIDO2_SECRET_H_
