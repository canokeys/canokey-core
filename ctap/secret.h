#ifndef CANOKEY_CORE_FIDO2_SECRET_H_
#define CANOKEY_CORE_FIDO2_SECRET_H_

#include <ctap.h>

int get_sign_counter(uint32_t *counter);
int increase_counter(uint32_t *counter);
int generate_key_handle(CredentialId *kh, uint8_t *pubkey);
size_t sign_with_device_key(const uint8_t *digest, uint8_t *sig);
size_t sign_with_private_key(const uint8_t *key, const uint8_t *digest, uint8_t *sig);
int verify_key_handle(const CredentialId *kh, uint8_t *pri_key);
int get_cert(uint8_t *buf);
int has_pin(void);
int set_pin(uint8_t *buf, uint8_t length);
int verify_pin_hash(uint8_t *buf);
int get_pin_retries(void);
int set_pin_retries(uint8_t ctr);

/**
 * Write the resident key to the specific index
 * @param rk The resident key to be written.
 * @param idx The index that the rk is written to. -1 for a newly added rk.
 * @return 0 for success; -1 for memory full; < -1 for IO error.
 */
int write_rk(CTAP_residentKey *rk, int idx);

#endif // CANOKEY_CORE_FIDO2_SECRET_H_
