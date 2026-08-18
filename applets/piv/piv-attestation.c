// SPDX-License-Identifier: Apache-2.0
#include "piv-attestation.h"

#include <apdu.h>
#include <applet-scratch.h>
#include <common.h>
#include <device-config.h>
#include <ecc.h>
#include <fs.h>
#include <key.h>
#include <memzero.h>
#include <rand.h>
#include <rsa.h>
#include <sha.h>

#define PIV_ATTESTATION_SIGNATURE_MAX 72
#define PIV_ATTESTATION_SERIAL_LENGTH 16
#define PIV_ATTESTATION_DEVICE_SERIAL_LENGTH 4
#define PIV_ATTESTATION_FILE_CHUNK 64

typedef struct {
  uint32_t value_off;
  uint32_t value_len;
  uint32_t total_len;
  uint8_t tag;
} piv_der_tlv_t;

typedef struct {
  uint32_t issuer_off;
  uint32_t issuer_len;
  uint32_t validity_off;
  uint32_t validity_len;
  uint16_t public_material_len;
  uint16_t rsa_modulus_off;
  uint16_t rsa_modulus_len;
  uint16_t rsa_exponent_off;
  uint8_t rsa_exponent_len;
  uint8_t rsa_modulus_pad;
  uint8_t rsa_exponent_pad;
  key_type_t target_type;
  uint8_t slot;
  uint8_t pin_policy;
  uint8_t touch_policy;
  uint8_t serial[PIV_ATTESTATION_SERIAL_LENGTH];
  uint8_t device_serial[PIV_ATTESTATION_DEVICE_SERIAL_LENGTH];
  uint8_t signature[PIV_ATTESTATION_SIGNATURE_MAX];
  uint8_t signature_len;
  const char *cert_path;
} piv_attestation_state_t;

enum {
  PIV_ATTESTATION_SEGMENT_ENCODED,
  PIV_ATTESTATION_SEGMENT_FILE,
  PIV_ATTESTATION_SEGMENT_PUBLIC,
};

typedef struct {
  uint16_t offset;
  uint16_t length;
  uint8_t source;
} piv_attestation_segment_t;

#define PIV_ATTESTATION_MAX_SEGMENTS 18
#define PIV_ATTESTATION_ENCODED_SIZE 256

// The fixed certificate schema needs at most 18 segments and 254 encoded
// bytes (RSA-4096 with a 72-byte signature). File and public-key bytes remain
// source-backed and therefore do not consume encoded space.
typedef struct {
  uint16_t total_len;
  uint16_t encoded_len;
  uint8_t count;
  piv_attestation_segment_t segments[PIV_ATTESTATION_MAX_SEGMENTS];
  uint8_t encoded[PIV_ATTESTATION_ENCODED_SIZE];
} piv_attestation_plan_t;

_Static_assert(sizeof(piv_attestation_plan_t) <= PIV_ATTESTATION_PLAN_SIZE,
               "PIV attestation plan exceeds its shared scratch reservation");

static piv_attestation_state_t piv_attestation_state;

static const uint8_t oid_ec_public_key[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const uint8_t oid_ed25519[] = {0x2B, 0x65, 0x70};
static const uint8_t oid_x25519[] = {0x2B, 0x65, 0x6E};
static const uint8_t der_ecdsa_with_sha256[] = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
static const uint8_t der_subject_prefix[] =
    "\x30\x25\x31\x23\x30\x21\x06\x03\x55\x04\x03\x0c\x1a"
    "CanoKey PIV Attestation ";
static const uint8_t der_extensions_serial_prefix[] =
    "\xa3\x28\x30\x26\x30\x12\x06\x0a\x2b\x06\x01\x04\x01\x82\xc4\x0a\x03\x07\x04\x04";
static const uint8_t der_extensions_policy_prefix[] =
    "\x30\x10\x06\x0a\x2b\x06\x01\x04\x01\x82\xc4\x0a\x03\x08\x04\x02";

static uint8_t piv_hex_nibble(uint8_t value) {
  return value < 10 ? (uint8_t)('0' + value) : (uint8_t)('a' + value - 10);
}

static uint8_t piv_der_header(uint8_t tag, uint32_t len, uint8_t out[4]) {
  out[0] = tag;
  if (len < 0x80) {
    out[1] = (uint8_t)len;
    return 2;
  }
  if (len <= 0xFF) {
    out[1] = 0x81;
    out[2] = (uint8_t)len;
    return 3;
  }
  out[1] = 0x82;
  out[2] = HI(len);
  out[3] = LO(len);
  return 4;
}

static int piv_file_read_exact(const char *path, uint32_t off, uint8_t *buf, uint16_t len) {
  return read_file(path, buf, off, len) == len ? 0 : -1;
}

static int piv_der_read_tlv(const char *path, uint32_t off, uint32_t limit, piv_der_tlv_t *tlv) {
  uint8_t header[4];
  if (off >= limit || piv_file_read_exact(path, off, header, 2) < 0) return -1;
  uint8_t header_len = 2;
  uint32_t value_len;
  if ((header[1] & 0x80u) == 0) {
    value_len = header[1];
  } else {
    const uint8_t count = header[1] & 0x7Fu;
    if (count == 0 || count > 2 || off + 2u + count > limit ||
        piv_file_read_exact(path, off + 2u, header + 2, count) < 0)
      return -1;
    header_len += count;
    value_len = 0;
    for (uint8_t i = 0; i < count; ++i)
      value_len = (value_len << 8u) | header[2 + i];
    if (value_len < 0x80) return -1;
  }
  if (off + header_len + value_len > limit) return -1;
  tlv->tag = header[0];
  tlv->value_off = off + header_len;
  tlv->value_len = value_len;
  tlv->total_len = header_len + value_len;
  return 0;
}

static int piv_attestation_parse_cert(const char *path, piv_attestation_state_t *state) {
  const int file_size = get_file_size(path);
  if (file_size <= 0) return SW_REFERENCE_DATA_NOT_FOUND;

  piv_der_tlv_t object;
  if (piv_der_read_tlv(path, 0, (uint32_t)file_size, &object) < 0 || object.tag != 0x53)
    return SW_REFERENCE_DATA_NOT_FOUND;

  uint32_t cert_off = 0;
  uint32_t cert_len = 0;
  uint32_t off = object.value_off;
  const uint32_t object_end = object.value_off + object.value_len;
  while (off < object_end) {
    piv_der_tlv_t field;
    if (piv_der_read_tlv(path, off, object_end, &field) < 0) return SW_REFERENCE_DATA_NOT_FOUND;
    if (field.tag == 0x70) {
      cert_off = field.value_off;
      cert_len = field.value_len;
      break;
    }
    off += field.total_len;
  }
  if (cert_len == 0) return SW_REFERENCE_DATA_NOT_FOUND;

  piv_der_tlv_t certificate;
  if (piv_der_read_tlv(path, cert_off, cert_off + cert_len, &certificate) < 0 || certificate.tag != 0x30 ||
      certificate.total_len != cert_len)
    return SW_REFERENCE_DATA_NOT_FOUND;

  piv_der_tlv_t tbs;
  if (piv_der_read_tlv(path, certificate.value_off, certificate.value_off + certificate.value_len, &tbs) < 0 ||
      tbs.tag != 0x30)
    return SW_REFERENCE_DATA_NOT_FOUND;

  off = tbs.value_off;
  const uint32_t tbs_end = tbs.value_off + tbs.value_len;
  piv_der_tlv_t field;
  if (piv_der_read_tlv(path, off, tbs_end, &field) < 0) return SW_REFERENCE_DATA_NOT_FOUND;
  if (field.tag == 0xA0) {
    off += field.total_len;
    if (piv_der_read_tlv(path, off, tbs_end, &field) < 0) return SW_REFERENCE_DATA_NOT_FOUND;
  }
  if (field.tag != 0x02) return SW_REFERENCE_DATA_NOT_FOUND; // serialNumber
  off += field.total_len;

  if (piv_der_read_tlv(path, off, tbs_end, &field) < 0 || field.tag != 0x30)
    return SW_REFERENCE_DATA_NOT_FOUND; // signature
  off += field.total_len;
  if (piv_der_read_tlv(path, off, tbs_end, &field) < 0 || field.tag != 0x30)
    return SW_REFERENCE_DATA_NOT_FOUND; // issuer
  off += field.total_len;

  if (piv_der_read_tlv(path, off, tbs_end, &field) < 0 || field.tag != 0x30)
    return SW_REFERENCE_DATA_NOT_FOUND; // validity
  state->validity_off = off;
  state->validity_len = field.total_len;
  off += field.total_len;

  if (piv_der_read_tlv(path, off, tbs_end, &field) < 0 || field.tag != 0x30)
    return SW_REFERENCE_DATA_NOT_FOUND; // subject
  state->issuer_off = off;
  state->issuer_len = field.total_len;
  return SW_NO_ERROR;
}

static void piv_attestation_plan_reset(piv_attestation_plan_t *plan) { memzero(plan, sizeof(*plan)); }

static void piv_attestation_plan_add_segment(piv_attestation_plan_t *plan, uint8_t source, uint16_t offset,
                                             uint16_t length) {
  piv_attestation_segment_t *segment = &plan->segments[plan->count++];
  segment->source = source;
  segment->offset = offset;
  segment->length = length;
  plan->total_len += length;
}

static void piv_attestation_plan_add_memory(piv_attestation_plan_t *plan, const uint8_t *data, uint16_t length) {
  const uint16_t offset = plan->encoded_len;
  memcpy(plan->encoded + offset, data, length);
  plan->encoded_len += length;

  if (plan->count > 0) {
    piv_attestation_segment_t *last = &plan->segments[plan->count - 1];
    if (last->source == PIV_ATTESTATION_SEGMENT_ENCODED && last->offset + last->length == offset) {
      last->length += length;
      plan->total_len += length;
      return;
    }
  }
  piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_ENCODED, offset, length);
}

static void piv_attestation_plan_start_memory(piv_attestation_plan_t *plan, const uint8_t *data, uint16_t length) {
  const uint16_t offset = plan->encoded_len;
  memcpy(plan->encoded + offset, data, length);
  plan->encoded_len += length;
  piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_ENCODED, offset, length);
}

static void piv_attestation_plan_add_header(piv_attestation_plan_t *plan, uint8_t tag, uint16_t length) {
  uint8_t header[4];
  piv_attestation_plan_add_memory(plan, header, piv_der_header(tag, length, header));
}

static void piv_attestation_plan_start_header(piv_attestation_plan_t *plan, uint8_t tag, uint16_t length) {
  uint8_t header[4];
  piv_attestation_plan_start_memory(plan, header, piv_der_header(tag, length, header));
}

static void piv_attestation_plan_insert_header(piv_attestation_plan_t *plan, uint8_t index, uint8_t tag,
                                               uint16_t content_len) {
  uint8_t header[4];
  const uint8_t header_len = piv_der_header(tag, content_len, header);
  const uint16_t offset = plan->encoded_len;
  memcpy(plan->encoded + offset, header, header_len);
  plan->encoded_len += header_len;
  memmove(&plan->segments[index + 1], &plan->segments[index],
          (plan->count - index) * sizeof(plan->segments[0]));
  plan->segments[index].source = PIV_ATTESTATION_SEGMENT_ENCODED;
  plan->segments[index].offset = offset;
  plan->segments[index].length = header_len;
  ++plan->count;
  plan->total_len += header_len;
}

static void piv_attestation_plan_add_oid(piv_attestation_plan_t *plan, const uint8_t *oid, uint8_t oid_len) {
  piv_attestation_plan_add_header(plan, 0x06, oid_len);
  piv_attestation_plan_add_memory(plan, oid, oid_len);
}

static void piv_attestation_plan_start_oid(piv_attestation_plan_t *plan, const uint8_t *oid, uint8_t oid_len) {
  piv_attestation_plan_start_header(plan, 0x06, oid_len);
  piv_attestation_plan_add_memory(plan, oid, oid_len);
}

static void piv_attestation_plan_add_subject(piv_attestation_plan_t *plan, uint8_t slot) {
  uint8_t slot_name[2] = {piv_hex_nibble(slot >> 4u), piv_hex_nibble(slot & 0x0Fu)};
  piv_attestation_plan_add_memory(plan, der_subject_prefix, sizeof(der_subject_prefix) - 1u);
  piv_attestation_plan_add_memory(plan, slot_name, sizeof(slot_name));
}

static int piv_attestation_plan_add_spki(piv_attestation_plan_t *plan, const piv_attestation_state_t *state) {
  static const uint8_t rsa_algorithm[] = {
      0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
  };
  const uint8_t spki_index = plan->count;
  const uint16_t spki_start = plan->total_len;

  if (IS_RSA(state->target_type)) {
    piv_attestation_plan_start_memory(plan, rsa_algorithm, sizeof(rsa_algorithm));

    const uint8_t bit_string_index = plan->count;
    const uint16_t bit_string_start = plan->total_len;
    piv_attestation_plan_start_memory(plan, (const uint8_t[]){0x00}, 1);

    const uint8_t rsa_index = plan->count;
    const uint16_t rsa_start = plan->total_len;
    piv_attestation_plan_start_header(plan, 0x02, state->rsa_modulus_len + state->rsa_modulus_pad);
    if (state->rsa_modulus_pad) piv_attestation_plan_add_memory(plan, (const uint8_t[]){0x00}, 1);
    piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_PUBLIC, state->rsa_modulus_off,
                                     state->rsa_modulus_len);
    piv_attestation_plan_add_header(plan, 0x02, state->rsa_exponent_len + state->rsa_exponent_pad);
    if (state->rsa_exponent_pad) piv_attestation_plan_add_memory(plan, (const uint8_t[]){0x00}, 1);
    piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_PUBLIC, state->rsa_exponent_off,
                                     state->rsa_exponent_len);
    piv_attestation_plan_insert_header(plan, rsa_index, 0x30, plan->total_len - rsa_start);
    piv_attestation_plan_insert_header(plan, bit_string_index, 0x03, plan->total_len - bit_string_start);
  } else if (IS_SHORT_WEIERSTRASS(state->target_type)) {
    const uint8_t *curve_oid;
    uint8_t curve_oid_len;
    if (ck_curve_oid(state->target_type, &curve_oid, &curve_oid_len) < 0) return -1;
    const uint8_t algorithm_index = plan->count;
    const uint16_t algorithm_start = plan->total_len;
    piv_attestation_plan_start_oid(plan, oid_ec_public_key, sizeof(oid_ec_public_key));
    piv_attestation_plan_add_oid(plan, curve_oid, curve_oid_len);
    piv_attestation_plan_insert_header(plan, algorithm_index, 0x30, plan->total_len - algorithm_start);

    const uint8_t bit_string_index = plan->count;
    const uint16_t bit_string_start = plan->total_len;
    piv_attestation_plan_start_memory(plan, (const uint8_t[]){0x00, 0x04}, 2);
    piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_PUBLIC, 0, state->public_material_len);
    piv_attestation_plan_insert_header(plan, bit_string_index, 0x03, plan->total_len - bit_string_start);
  } else if (state->target_type == ED25519 || state->target_type == X25519) {
    const uint8_t *algorithm_oid = state->target_type == ED25519 ? oid_ed25519 : oid_x25519;
    const uint8_t algorithm_index = plan->count;
    const uint16_t algorithm_start = plan->total_len;
    piv_attestation_plan_start_oid(plan, algorithm_oid, 3);
    piv_attestation_plan_insert_header(plan, algorithm_index, 0x30, plan->total_len - algorithm_start);

    const uint8_t bit_string_index = plan->count;
    const uint16_t bit_string_start = plan->total_len;
    piv_attestation_plan_start_memory(plan, (const uint8_t[]){0x00}, 1);
    piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_PUBLIC, 0, state->public_material_len);
    piv_attestation_plan_insert_header(plan, bit_string_index, 0x03, plan->total_len - bit_string_start);
  } else {
    return -1;
  }

  piv_attestation_plan_insert_header(plan, spki_index, 0x30, plan->total_len - spki_start);
  return 0;
}

static int piv_attestation_plan_build_tbs(piv_attestation_plan_t *plan, const piv_attestation_state_t *state) {
  static const uint8_t version[] = {0xA0, 0x03, 0x02, 0x01, 0x02};
  const uint8_t serial_pad = (state->serial[0] & 0x80u) != 0;
  const uint8_t policy[2] = {state->pin_policy, state->touch_policy};

  piv_attestation_plan_reset(plan);
  piv_attestation_plan_add_memory(plan, version, sizeof(version));
  piv_attestation_plan_add_header(plan, 0x02, sizeof(state->serial) + serial_pad);
  if (serial_pad) piv_attestation_plan_add_memory(plan, (const uint8_t[]){0x00}, 1);
  piv_attestation_plan_add_memory(plan, state->serial, sizeof(state->serial));
  piv_attestation_plan_add_memory(plan, der_ecdsa_with_sha256, sizeof(der_ecdsa_with_sha256) - 1u);
  piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_FILE, state->issuer_off, state->issuer_len);
  piv_attestation_plan_add_segment(plan, PIV_ATTESTATION_SEGMENT_FILE, state->validity_off, state->validity_len);
  piv_attestation_plan_add_subject(plan, state->slot);
  if (piv_attestation_plan_add_spki(plan, state) < 0) return -1;
  piv_attestation_plan_add_memory(plan, der_extensions_serial_prefix, sizeof(der_extensions_serial_prefix) - 1u);
  piv_attestation_plan_add_memory(plan, state->device_serial, sizeof(state->device_serial));
  piv_attestation_plan_add_memory(plan, der_extensions_policy_prefix, sizeof(der_extensions_policy_prefix) - 1u);
  piv_attestation_plan_add_memory(plan, policy, sizeof(policy));
  piv_attestation_plan_insert_header(plan, 0, 0x30, plan->total_len);
  return 0;
}

static int piv_attestation_plan_build_certificate(piv_attestation_plan_t *plan,
                                                  const piv_attestation_state_t *state) {
  if (piv_attestation_plan_build_tbs(plan, state) < 0) return -1;
  piv_attestation_plan_add_memory(plan, der_ecdsa_with_sha256, sizeof(der_ecdsa_with_sha256) - 1u);
  piv_attestation_plan_add_header(plan, 0x03, 1u + state->signature_len);
  piv_attestation_plan_add_memory(plan, (const uint8_t[]){0x00}, 1);
  piv_attestation_plan_add_memory(plan, state->signature, state->signature_len);
  piv_attestation_plan_insert_header(plan, 0, 0x30, plan->total_len);
  return 0;
}

static int piv_attestation_plan_read(const piv_attestation_plan_t *plan, uint16_t offset, uint8_t *buf,
                                     uint16_t len) {
  if (offset > plan->total_len || len > plan->total_len - offset) return -1;
  uint16_t stream_off = 0;
  uint16_t copied = 0;
  for (uint8_t i = 0; i < plan->count && copied < len; ++i) {
    const piv_attestation_segment_t *segment = &plan->segments[i];
    const uint16_t segment_end = stream_off + segment->length;
    if (segment_end > offset && stream_off < offset + len) {
      const uint16_t copy_start = MAX(stream_off, offset);
      const uint16_t copy_end = MIN(segment_end, offset + len);
      const uint16_t source_off = segment->offset + copy_start - stream_off;
      const uint16_t copy_len = copy_end - copy_start;
      if (segment->source == PIV_ATTESTATION_SEGMENT_FILE) {
        if (piv_file_read_exact(piv_attestation_state.cert_path, source_off, buf + copied, copy_len) < 0) return -1;
      } else {
        const uint8_t *source = segment->source == PIV_ATTESTATION_SEGMENT_PUBLIC
                                    ? applet_session_scratch.piv_attestation.public_material
                                    : plan->encoded;
        memcpy(buf + copied, source + source_off, copy_len);
      }
      copied += copy_len;
    }
    stream_off = segment_end;
  }
  return copied == len ? len : -1;
}

static int piv_attestation_response_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  UNUSED(ctx);
  piv_attestation_plan_t *plan = (piv_attestation_plan_t *)applet_session_scratch.piv_attestation.work.attestation_plan;
  if (offset > UINT16_MAX) return -1;
  return piv_attestation_plan_read(plan, (uint16_t)offset, buf, len);
}

static void piv_attestation_response_close(void *ctx) {
  memzero(&applet_session_scratch.piv_attestation, sizeof(applet_session_scratch.piv_attestation));
  memzero(ctx, sizeof(piv_attestation_state));
}

static int piv_attestation_build_public(const char *path, piv_attestation_state_t *state,
                                        piv_attestation_scratch_t *scratch) {
  key_meta_t meta;
  if (ck_read_key_metadata(path, &meta) < 0 || meta.type == KEY_TYPE_PKC_END || meta.origin != KEY_ORIGIN_GENERATED) {
    return SW_REFERENCE_DATA_NOT_FOUND;
  }

  state->target_type = meta.type;
  state->pin_policy = meta.pin_policy;
  state->touch_policy = meta.touch_policy;
  if (IS_RSA(meta.type)) {
    const uint16_t modulus_len = (uint16_t)PUBLIC_KEY_LENGTH[meta.type];
    if ((uint32_t)modulus_len + E_LENGTH > sizeof(scratch->public_material) ||
        read_file(path, &scratch->work.rsa, 0, sizeof(scratch->work.rsa)) != sizeof(scratch->work.rsa) ||
        rsa_get_public_key(&scratch->work.rsa, scratch->public_material) < 0) {
      memzero(&scratch->work, sizeof(scratch->work));
      return -1;
    }
    memcpy(scratch->public_material + modulus_len, scratch->work.rsa.e, E_LENGTH);
    state->public_material_len = modulus_len + E_LENGTH;
    state->rsa_modulus_off = 0;
    while (state->rsa_modulus_off + 1 < modulus_len && scratch->public_material[state->rsa_modulus_off] == 0)
      ++state->rsa_modulus_off;
    state->rsa_modulus_len = modulus_len - state->rsa_modulus_off;
    state->rsa_modulus_pad = (scratch->public_material[state->rsa_modulus_off] & 0x80u) != 0;
    state->rsa_exponent_off = modulus_len;
    while (state->rsa_exponent_off + 1 < modulus_len + E_LENGTH &&
           scratch->public_material[state->rsa_exponent_off] == 0)
      ++state->rsa_exponent_off;
    state->rsa_exponent_len = (uint8_t)(modulus_len + E_LENGTH - state->rsa_exponent_off);
    state->rsa_exponent_pad = (scratch->public_material[state->rsa_exponent_off] & 0x80u) != 0;
  } else if (IS_ECC(meta.type)) {
    const uint16_t public_len = (uint16_t)PUBLIC_KEY_LENGTH[meta.type];
    if (public_len > sizeof(scratch->public_material) ||
        read_file(path, &scratch->work.ecc, 0, sizeof(scratch->work.ecc)) != sizeof(scratch->work.ecc)) {
      memzero(&scratch->work, sizeof(scratch->work));
      return -1;
    }
    memcpy(scratch->public_material, scratch->work.ecc.pub, public_len);
    if (meta.type == X25519) swap_big_number_endian(scratch->public_material);
    state->public_material_len = public_len;
  } else {
    memzero(&scratch->work, sizeof(scratch->work));
    return SW_WRONG_DATA;
  }
  memzero(&scratch->work, sizeof(scratch->work));
  return SW_NO_ERROR;
}

static int piv_attestation_sign(const char *path, piv_attestation_scratch_t *scratch, uint8_t signature[72]) {
  key_meta_t meta;
  if (ck_read_key_metadata(path, &meta) < 0 || meta.type != SECP256R1 ||
      read_file(path, &scratch->work.ecc, 0, sizeof(scratch->work.ecc)) != sizeof(scratch->work.ecc)) {
    memzero(&scratch->work, sizeof(scratch->work));
    return SW_REFERENCE_DATA_NOT_FOUND;
  }
  const size_t signature_len = ecdsa_p256_sign_der(&scratch->work.ecc, scratch->digest, signature);
  memzero(&scratch->work, sizeof(scratch->work));
  return signature_len == 0 ? -1 : (int)signature_len;
}

__attribute__((noinline)) static int piv_attestation_hash_tbs(piv_attestation_scratch_t *scratch,
                                                              const piv_attestation_plan_t *plan) {
  sha256_ctx_t sha256;
  uint8_t chunk[PIV_ATTESTATION_FILE_CHUNK];
  sha256_init(&sha256);
  for (uint16_t offset = 0; offset < plan->total_len;) {
    const uint16_t length = MIN((uint16_t)sizeof(chunk), plan->total_len - offset);
    if (piv_attestation_plan_read(plan, offset, chunk, length) < 0) {
      memzero(chunk, sizeof(chunk));
      return -1;
    }
    sha256_update(&sha256, chunk, length);
    offset += length;
  }
  sha256_final(&sha256, scratch->digest);
  memzero(chunk, sizeof(chunk));
  return 0;
}

int piv_attestation_generate(uint8_t slot, const char *target_key_path, const char *attestation_key_path,
                             const char *attestation_cert_path) {
  apdu_response_source_clear();
  memzero(&piv_attestation_state, sizeof(piv_attestation_state));
  piv_attestation_state.cert_path = attestation_cert_path;
  piv_attestation_state.slot = slot;

  int ret = piv_attestation_parse_cert(attestation_cert_path, &piv_attestation_state);
  if (ret != SW_NO_ERROR) return ret;

  piv_attestation_scratch_t *scratch = &applet_session_scratch.piv_attestation;
  ret = piv_attestation_build_public(target_key_path, &piv_attestation_state, scratch);
  if (ret != SW_NO_ERROR) return ret;

  random_buffer(piv_attestation_state.serial, sizeof(piv_attestation_state.serial));
  uint8_t serial_nonzero = 0;
  for (size_t i = 0; i < sizeof(piv_attestation_state.serial); ++i)
    serial_nonzero |= piv_attestation_state.serial[i];
  if (serial_nonzero == 0) piv_attestation_state.serial[sizeof(piv_attestation_state.serial) - 1] = 1;
  device_config_fill_serial(piv_attestation_state.device_serial);

  piv_attestation_plan_t *plan = (piv_attestation_plan_t *)scratch->work.attestation_plan;
  if (piv_attestation_plan_build_tbs(plan, &piv_attestation_state) < 0) return SW_WRONG_DATA;
  if (piv_attestation_hash_tbs(scratch, plan) < 0) return -1;

  ret = piv_attestation_sign(attestation_key_path, scratch, piv_attestation_state.signature);
  memzero(scratch->digest, sizeof(scratch->digest));
  if (ret < 0) return ret;
  if (ret > PIV_ATTESTATION_SIGNATURE_MAX) return -1;
  piv_attestation_state.signature_len = (uint8_t)ret;

  if (piv_attestation_plan_build_certificate(plan, &piv_attestation_state) < 0) return -1;
  apdu_response_source_set(plan->total_len, SW_NO_ERROR, piv_attestation_response_read, piv_attestation_response_close,
                           &piv_attestation_state);
  return SW_NO_ERROR;
}
