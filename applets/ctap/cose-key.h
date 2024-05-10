/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_FIDO2_COSE_KEY_H_
#define CANOKEY_CORE_FIDO2_COSE_KEY_H_

#define COSE_KEY_LABEL_KTY 1
#define COSE_KEY_LABEL_ALG 3
#define COSE_KEY_LABEL_CRV -1
#define COSE_KEY_LABEL_X   -2
#define COSE_KEY_LABEL_Y   -3

#define COSE_KEY_KTY_OKP 1
#define COSE_KEY_KTY_EC2 2

#define COSE_KEY_CRV_P256    1
#define COSE_KEY_CRV_ED25519 6

#define COSE_ALG_ES256            -7
#define COSE_ALG_EDDSA            -8
#define COSE_ALG_ECDH_ES_HKDF_256 -25

#endif // CANOKEY_CORE_FIDO2_COSE_KEY_H_
