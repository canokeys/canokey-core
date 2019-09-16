#ifndef CANOKEY_CORE_FIDO2_SECRET_H_
#define CANOKEY_CORE_FIDO2_SECRET_H_

#include <ctap.h>

int get_sign_counter(uint32_t *counter);
int increase_counter(uint32_t *counter);
int generate_key_handle(CredentialId *kh, uint8_t *pubkey);
size_t sign_with_device_key(const uint8_t *digest, uint8_t *sig);
size_t sign_with_private_key(const uint8_t *key, const uint8_t *digest, uint8_t *sig);
int verify_key_handle(CredentialId *kh);
int get_cert(uint8_t *buf);
int has_pin(void);
int set_pin(uint8_t *buf, uint8_t length);
int verify_pin_hash(uint8_t *buf);
int get_pin_retries(void);
int set_pin_retries(uint8_t ctr);

/**
 * Find the resident key by the given credential id (passed in rk)
 * @param rk credential id in the resident key will be used to find the corresponding one, and once the rk is found,
 *           the rk will be filled.
 * @return -2 for error
 *         -1 for not found
 *         >=0 for index
 */
int find_rk_by_credential_id(CTAP_residentKey *rk);

#endif // CANOKEY_CORE_FIDO2_SECRET_H_
