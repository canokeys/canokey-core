// SPDX-License-Identifier: Apache-2.0
#ifndef CK_RUST_CRYPTO_OPS_H
#define CK_RUST_CRYPTO_OPS_H
// Stable ABI, mirrored by the enums in rust/core/src/ports/crypto.rs.
enum ck_key_operation {
  CK_KEY_GENERATE = 0,
  CK_KEY_VALIDATE = 1,
  CK_KEY_PUBLIC = 2,
  CK_KEY_RSA_PKCS1_SIGN = 3,
  CK_KEY_RSA_PKCS1_DECIPHER = 4,
  CK_KEY_AGREE = 5,
  CK_KEY_EC_SIGN = 6,
  CK_KEY_RSA_RAW = 7,
  CK_KEY_SM2_EXCHANGE = 8,
};
enum ck_stream_operation {
  CK_STREAM_PUBLIC_INIT = 0,
  CK_STREAM_READ = 1,
  CK_STREAM_SIGN_INIT = 2,
  CK_STREAM_SIGN_UPDATE = 3,
  CK_STREAM_SIGN_FINAL = 4,
  CK_STREAM_ABORT = 5,
  CK_STREAM_DECAPSULATE_INIT = 6,
  CK_STREAM_DECAPSULATE_UPDATE = 7,
  CK_STREAM_DECAPSULATE_FINAL = 8,
  CK_STREAM_SM2_IDENTITY = 9,
};
enum ck_digest_operation {
  CK_DIGEST_INIT = 0,
  CK_DIGEST_UPDATE = 1,
  CK_DIGEST_FINAL = 2,
  CK_DIGEST_ABORT = 3,
};
#endif
