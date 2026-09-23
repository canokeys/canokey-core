// SPDX-License-Identifier: Apache-2.0
// Host-only implementation of the primitive port; OpenSSL owns test allocations.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>
static const unsigned widths[] = {32, 32, 48, 32, 32, 128, 192, 256, 66};
static RSA *decode_rsa(uint8_t alg, const uint8_t *key) {
  BN_CTX *ctx = BN_CTX_new();
  RSA *rsa = RSA_new();
  BIGNUM *e = BN_bin2bn(key, 4, NULL), *p = BN_bin2bn(key + 4, widths[alg], NULL),
         *q = BN_bin2bn(key + 260, widths[alg], NULL);
  BIGNUM *n = BN_new(), *pm = BN_dup(p), *qm = BN_dup(q), *phi = BN_new(), *d = NULL;
  if (!ctx || !rsa || !e || !p || !q || !n || !pm || !qm || !phi) goto fail;
  if (!BN_mul(n, p, q, ctx) || !BN_sub_word(pm, 1) || !BN_sub_word(qm, 1) || !BN_mul(phi, pm, qm, ctx)) goto fail;
  d = BN_mod_inverse(NULL, e, phi, ctx);
  if (!d) goto fail;
  if (!RSA_set0_key(rsa, n, e, d)) goto fail;
  n = e = d = NULL;
  if (!RSA_set0_factors(rsa, p, q)) goto fail;
  p = q = NULL;
  BIGNUM *dp = BN_bin2bn(key + 516, widths[alg], NULL), *dq = BN_bin2bn(key + 772, widths[alg], NULL),
         *qi = BN_bin2bn(key + 1028, widths[alg], NULL);
  if (!dp || !dq || !qi || !RSA_set0_crt_params(rsa, dp, dq, qi)) {
    BN_clear_free(dp);
    BN_clear_free(dq);
    BN_clear_free(qi);
    goto fail;
  }
  goto done;
fail:
  RSA_free(rsa);
  rsa = NULL;
done:
  BN_CTX_free(ctx);
  BN_clear_free(e);
  BN_clear_free(p);
  BN_clear_free(q);
  BN_clear_free(n);
  BN_clear_free(pm);
  BN_clear_free(qm);
  BN_clear_free(phi);
  BN_clear_free(d);
  return rsa;
}
static int rsa_op(uint8_t op, uint8_t alg, uint8_t *key, const uint8_t *in, size_t len, uint8_t *out) {
  int result = -1;
  RSA *rsa = NULL;
  if (op == 0) {
    rsa = RSA_new();
    BIGNUM *e = BN_new();
    if (!rsa || !e || !BN_set_word(e, 65537) || !RSA_generate_key_ex(rsa, widths[alg] * 16, e, NULL)) {
      BN_free(e);
      goto done;
    }
    BN_free(e);
    const BIGNUM *p, *q, *dp, *dq, *qi, *exp;
    RSA_get0_key(rsa, NULL, &exp, NULL);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dp, &dq, &qi);
    memset(key, 0, 1284);
    BN_bn2binpad(exp, key, 4);
    BN_bn2binpad(p, key + 4, widths[alg]);
    BN_bn2binpad(q, key + 260, widths[alg]);
    BN_bn2binpad(dp, key + 516, widths[alg]);
    BN_bn2binpad(dq, key + 772, widths[alg]);
    BN_bn2binpad(qi, key + 1028, widths[alg]);
    result = 0;
    goto done;
  }
  rsa = decode_rsa(alg, key);
  if (!rsa) goto done;
  switch (op) {
  case 1:
    result = RSA_check_key(rsa) == 1 ? 0 : -1;
    break;
  case 2: {
    const BIGNUM *n;
    RSA_get0_key(rsa, &n, NULL, NULL);
    result = BN_bn2binpad(n, out, widths[alg] * 2);
    break;
  }
  case 3:
    result = RSA_private_encrypt((int)len, in, out, rsa, RSA_PKCS1_PADDING);
    break;
  case 4:
    result = RSA_private_decrypt((int)len, in, out, rsa, RSA_PKCS1_PADDING);
    break;
  default:
    break;
  }
done:
  RSA_free(rsa);
  return result;
}
static int curve_op(uint8_t op, uint8_t alg, uint8_t *key, const uint8_t *in, size_t len, uint8_t *out) {
  static const int curves[] = {NID_X9_62_prime256v1, NID_secp256k1, NID_secp384r1, 0, 0, 0, 0, 0, NID_secp521r1};
  int result = -1;
  EC_KEY *ec = EC_KEY_new_by_curve_name(curves[alg]);
  if (!ec) return -1;
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  EC_POINT *pub = EC_POINT_new(group);
  BIGNUM *k = NULL;
  BN_CTX *ctx = BN_CTX_new();
  if (!pub || !ctx) goto done;
  if (op == 0) {
    if (EC_KEY_generate_key(ec) != 1) goto done;
    result = BN_bn2binpad(EC_KEY_get0_private_key(ec), key, widths[alg]) == (int)widths[alg] ? 0 : -1;
    goto done;
  }
  k = BN_bin2bn(key, widths[alg], NULL);
  if (!k || EC_KEY_set_private_key(ec, k) != 1 || EC_POINT_mul(group, pub, k, NULL, NULL, ctx) != 1 ||
      EC_KEY_set_public_key(ec, pub) != 1 || EC_KEY_check_key(ec) != 1)
    goto done;
  if (op == 1) {
    result = 0;
    goto done;
  }
  if (op == 2) {
    uint8_t b[133];
    size_t n = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, b, sizeof(b), ctx);
    if (n > 0) {
      memcpy(out, b + 1, n - 1);
      result = (int)n - 1;
    }
    goto done;
  }
  if (op == 6) {
    if (alg == 8 && len == 66) {
      in++;
      len--;
    }
    ECDSA_SIG *sig = ECDSA_do_sign(in, (int)len, ec);
    if (!sig) goto done;
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2binpad(r, out, widths[alg]);
    BN_bn2binpad(s, out + widths[alg], widths[alg]);
    result = 2 * widths[alg];
    ECDSA_SIG_free(sig);
    goto done;
  }
  if (op == 5) {
    uint8_t b[133];
    if (len != widths[alg] * 2) goto done;
    b[0] = 4;
    memcpy(b + 1, in, len);
    if (EC_POINT_oct2point(group, pub, b, len + 1, ctx) != 1 || EC_POINT_is_on_curve(group, pub, ctx) != 1) goto done;
    result = ECDH_compute_key(out, widths[alg], pub, ec, NULL);
  }
done:
  BN_clear_free(k);
  BN_CTX_free(ctx);
  EC_POINT_free(pub);
  EC_KEY_free(ec);
  return result;
}
static int raw_op(uint8_t op, uint8_t alg, uint8_t *key, const uint8_t *in, size_t len, uint8_t *out) {
  int result = -1;
  uint8_t private[32];
  int type = alg == 3 ? EVP_PKEY_ED25519 : EVP_PKEY_X25519;
  if (op == 0) {
    if (RAND_bytes(key, 32) != 1) return -1;
    if (alg == 4) {
      key[31] &= 248;
      key[0] &= 127;
      key[0] |= 64;
    }
    return 0;
  }
  for (unsigned i = 0; i < 32; i++)
    private[i] = key[alg == 4 ? 31 - i : i];
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(type, NULL, private, 32);
  OPENSSL_cleanse(private, 32);
  if (!k) return -1;
  if (op == 1) result = 0;
  if (op == 2) {
    size_t n = 32;
    if (EVP_PKEY_get_raw_public_key(k, out, &n) == 1) result = (int)n;
  }
  if (op == 6 && alg == 3) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t n = 64;
    if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, k) == 1 && EVP_DigestSign(ctx, out, &n, in, len) == 1)
      result = (int)n;
    EVP_MD_CTX_free(ctx);
  }
  if (op == 5 && alg == 4 && len == 32) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(type, NULL, in, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(k, NULL);
    size_t n = 32;
    if (peer && ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, out, &n) == 1)
      result = (int)n;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
  }
  EVP_PKEY_free(k);
  return result;
}
typedef struct {
  uint16_t bits, reserved;
  uint8_t bytes[1284];
} KeyMaterial;
int32_t ck_platform_key(uint8_t op, uint8_t alg, KeyMaterial *material, const uint8_t *in, size_t n, uint8_t *out,
                        size_t cap) {
  if (alg > 8 || cap < 512) return -1;
  uint8_t *key = material->bytes;
  if (alg >= 5 && alg <= 7) return rsa_op(op, alg, key, in, n, out);
  if (alg == 3 || alg == 4) return raw_op(op, alg, key, in, n, out);
  return curve_op(op, alg, key, in, n, out);
}
