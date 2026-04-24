// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-internal.h"
#include "ctap-parser.h"
#include "secret.h"
#include "u2f.h"
#include <applet-scratch.h>
#include <block-cipher.h>
#include <cbor.h>
#include <common.h>
#include <crypto-util.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <hmac.h>
#include <ml-dsa-65.h>
#include <memzero.h>
#include <rand.h>
#include <string.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if ((ret) != 0) ERR_MSG("CHECK_PARSER_RET %#x\n", ret);                                                            \
    if ((ret) > 0) return ret;                                                                                         \
  } while (0)

#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if ((ret) != 0) ERR_MSG("CHECK_CBOR_RET %#x\n", ret);                                                              \
    if ((ret) != 0) return CTAP2_ERR_INVALID_CBOR;                                                                     \
  } while (0)

#define SET_RESP()                                                                                                     \
  do {                                                                                                                 \
    if (*resp == 0)                                                                                                    \
      *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1);                                                \
    else                                                                                                               \
      *resp_len = 1;                                                                                                   \
  } while (0)

#define WAIT(timeout_response)                                                                                         \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    switch (wait_for_user_presence(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID)) {          \
    case USER_PRESENCE_CANCEL:                                                                                         \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      return timeout_response;                                                                                         \
    }                                                                                                                  \
  } while (0)

#define KEEPALIVE()                                                                                                    \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    send_keepalive_during_processing(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID);          \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};

// pin & command states
static uint8_t consecutive_pin_counter, last_cmd;
// source of APDU in process
static ctap_src_t current_cmd_src;
// SM2 attr
CTAP_sm2_attr ctap_sm2_attr;

typedef struct {
  uint8_t *buf;
  size_t len;
  size_t emitted;
} CTAP_mem_stream_state;

#define CTAP_MC_STREAM_MAX_SEGMENTS 5

typedef enum {
  CTAP_MC_STREAM_SEG_MEM,
  CTAP_MC_STREAM_SEG_FILE,
  CTAP_MC_STREAM_SEG_MLDSA,
} CTAP_make_credential_stream_segment_kind;

typedef struct {
  CTAP_make_credential_stream_segment_kind kind;
  const uint8_t *buf;
  const char *path;
  CTAP_mldsa_stream_state *mldsa;
  size_t file_off;
  size_t len;
  size_t off;
} CTAP_make_credential_stream_segment;

typedef struct {
  CTAP_make_credential_stream_segment segments[CTAP_MC_STREAM_MAX_SEGMENTS];
  size_t segment_count;
  size_t current_segment;
  size_t total_len;
  bool prepared;
} CTAP_make_credential_stream_state;

static CTAP_make_credential_stream_state mc_stream_state;
static CTAP_mem_stream_state mem_stream_state;
#define mldsa_stream_state applet_session_scratch.ctap_mldsa
static uint8_t *stream_resp_base;
static bool stream_make_credential_response;

static int ctap_mem_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_mem_stream_state *state = (CTAP_mem_stream_state *)ctx;
  size_t copied = MIN(state->len - state->emitted, max_len);
  if (copied != 0) memcpy(out, state->buf + state->emitted, copied);
  state->emitted += copied;
  *written = copied;
  return 0;
}

static int cbor_put_uint(uint8_t **p, uint64_t v, uint8_t major) {
  if (v < 24) {
    *(*p)++ = major | (uint8_t)v;
  } else if (v <= UINT8_MAX) {
    *(*p)++ = major | 24;
    *(*p)++ = (uint8_t)v;
  } else if (v <= UINT16_MAX) {
    *(*p)++ = major | 25;
    *(*p)++ = (uint8_t)(v >> 8);
    *(*p)++ = (uint8_t)v;
  } else {
    return -1;
  }
  return 0;
}

static int cbor_put_int(uint8_t **p, int64_t v) {
  if (v >= 0) return cbor_put_uint(p, (uint64_t)v, 0x00);
  return cbor_put_uint(p, (uint64_t)(-1 - v), 0x20);
}

static int cbor_put_bytes_header(uint8_t **p, size_t len) { return cbor_put_uint(p, len, 0x40); }

static int cbor_put_text(uint8_t **p, const char *s) {
  size_t len = strlen(s);
  if (cbor_put_uint(p, len, 0x60) < 0) return -1;
  memcpy(*p, s, len);
  *p += len;
  return 0;
}

static int cbor_put_mldsa65_cose_prefix(uint8_t **p) {
  if (cbor_put_uint(p, 3, 0xA0) < 0) return -1;
  if (cbor_put_int(p, COSE_KEY_LABEL_KTY) < 0 || cbor_put_int(p, COSE_KEY_KTY_AKP) < 0) return -1;
  if (cbor_put_int(p, COSE_KEY_LABEL_ALG) < 0 || cbor_put_int(p, COSE_ALG_ML_DSA_65) < 0) return -1;
  if (cbor_put_int(p, COSE_KEY_LABEL_AKP_PUB) < 0 || cbor_put_bytes_header(p, MLDSA_PK_BYTES) < 0) return -1;
  return 0;
}

static int ctap_mldsa_stream_fill_stage(CTAP_mldsa_stream_state *state) {
  int ret;
  state->stage_len = 0;
  state->stage_off = 0;
  if (state->kind == CTAP_MLDSA_STREAM_PK) {
    if (state->keygen.phase == 0) memcpy(state->keygen.seed, state->seed, PRI_KEY_SIZE);
    ret = ml_dsa_65_keygen_streaming(state->stage, APDU_BUFFER_SIZE, &state->keygen, NULL);
  } else if (state->kind == CTAP_MLDSA_STREAM_SIG) {
    if (state->sign.phase == 0) memcpy(state->sign.seed, state->seed, PRI_KEY_SIZE);
    ret = ml_dsa_65_sign_seed_streaming(state->stage, APDU_BUFFER_SIZE, &state->sign, state->msg, state->msg_len, NULL,
                                        0, state->tr);
  } else {
    return -1;
  }
  if (ret < 0) return -1;
  state->stage_len = (size_t)ret;
  return 0;
}

static int ctap_mldsa_stream_read_generated(CTAP_mldsa_stream_state *state, uint8_t *out, size_t max_len,
                                            size_t *written) {
  size_t copied = 0;

  while (copied < max_len && state->kind != CTAP_MLDSA_STREAM_NONE) {
    if (state->stage_off == state->stage_len) {
      if ((state->kind == CTAP_MLDSA_STREAM_PK && state->keygen.phase == 0 && state->stage_len != 0) ||
          (state->kind == CTAP_MLDSA_STREAM_SIG && state->sign.phase == 0 && state->stage_len != 0)) {
        state->kind = CTAP_MLDSA_STREAM_NONE;
        break;
      }
      if (ctap_mldsa_stream_fill_stage(state) < 0) return -1;
      if (state->stage_len == 0) return -1;
    }

    size_t n = MIN(state->stage_len - state->stage_off, max_len - copied);
    memcpy(out + copied, state->stage + state->stage_off, n);
    state->stage_off += n;
    copied += n;
  }

  *written = copied;
  return 0;
}

static int ctap_mldsa_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_mldsa_stream_state *state = (CTAP_mldsa_stream_state *)ctx;
  size_t copied = 0;

  while (copied < max_len) {
    if (state->prefix_off < state->prefix_len) {
      size_t n = MIN(state->prefix_len - state->prefix_off, max_len - copied);
      memcpy(out + copied, state->prefix + state->prefix_off, n);
      state->prefix_off += n;
      copied += n;
      continue;
    }

    if (state->kind != CTAP_MLDSA_STREAM_NONE) {
      size_t n = 0;
      if (ctap_mldsa_stream_read_generated(state, out + copied, max_len - copied, &n) < 0) return -1;
      copied += n;
      if (n != 0) continue;
    }

    if (state->suffix_off < state->suffix_len) {
      size_t n = MIN(state->suffix_len - state->suffix_off, max_len - copied);
      memcpy(out + copied, state->suffix + state->suffix_off, n);
      state->suffix_off += n;
      copied += n;
      continue;
    }
    break;
  }

  *written = copied;
  return 0;
}

static int ctap_mldsa65_tr_from_seed(const uint8_t seed[PRI_KEY_SIZE], uint8_t tr[MLDSA_TRBYTES]) {
  mldsa_keygen_state_t st = {0};
  int ret;
  memcpy(st.seed, seed, PRI_KEY_SIZE);
  ret = ml_dsa_65_keygen_streaming(global_buffer, APDU_BUFFER_SIZE, &st, tr);
  if (ret < 0) return -1;
  while (st.phase != 0) {
    ret = ml_dsa_65_keygen_streaming(global_buffer, APDU_BUFFER_SIZE, &st, NULL);
    if (ret < 0) return -1;
  }
  return 0;
}

static void ctap_hid_stream_close(void *ctx) {
  (void)ctx;
  release_apdu_buffer(BUFFER_OWNER_CTAPHID);
}

static int ctap_make_credential_stream_add_segment(CTAP_make_credential_stream_segment_kind kind, const uint8_t *buf,
                                                   const char *path, CTAP_mldsa_stream_state *mldsa, size_t file_off,
                                                   size_t len) {
  if (mc_stream_state.segment_count >= CTAP_MC_STREAM_MAX_SEGMENTS) return -1;
  CTAP_make_credential_stream_segment *segment = &mc_stream_state.segments[mc_stream_state.segment_count++];
  segment->kind = kind;
  segment->buf = buf;
  segment->path = path;
  segment->mldsa = mldsa;
  segment->file_off = file_off;
  segment->len = len;
  segment->off = 0;
  mc_stream_state.total_len += len;
  mc_stream_state.prepared = true;
  return 0;
}

static int ctap_make_credential_stream_add_mem(const uint8_t *buf, size_t len) {
  return ctap_make_credential_stream_add_segment(CTAP_MC_STREAM_SEG_MEM, buf, NULL, NULL, 0, len);
}

static int ctap_make_credential_stream_add_file(const char *path, size_t file_off, size_t len) {
  return ctap_make_credential_stream_add_segment(CTAP_MC_STREAM_SEG_FILE, NULL, path, NULL, file_off, len);
}

static int ctap_make_credential_stream_add_mldsa(CTAP_mldsa_stream_state *mldsa, size_t len) {
  return ctap_make_credential_stream_add_segment(CTAP_MC_STREAM_SEG_MLDSA, NULL, NULL, mldsa, 0, len);
}

static int ctap_make_credential_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_make_credential_stream_state *state = (CTAP_make_credential_stream_state *)ctx;
  size_t copied = 0;

  while (copied < max_len && state->current_segment < state->segment_count) {
    CTAP_make_credential_stream_segment *segment = &state->segments[state->current_segment];
    if (segment->off == segment->len) {
      ++state->current_segment;
      continue;
    }

    size_t n = MIN(segment->len - segment->off, max_len - copied);
    size_t written_now = n;
    switch (segment->kind) {
    case CTAP_MC_STREAM_SEG_MEM:
      memcpy(out + copied, segment->buf + segment->off, n);
      break;
    case CTAP_MC_STREAM_SEG_FILE:
      if (read_file(segment->path, out + copied, segment->file_off + segment->off, n) < 0) return -1;
      break;
    case CTAP_MC_STREAM_SEG_MLDSA:
      if (ctap_mldsa_stream_read_generated(segment->mldsa, out + copied, n, &written_now) < 0) return -1;
      if (written_now == 0) return -1;
      break;
    }
    segment->off += written_now;
    copied += written_now;
  }

  *written = copied;
  return 0;
}

uint8_t ctap_install(uint8_t reset) {
  consecutive_pin_counter = 3;
  last_cmd = CTAP_INVALID_CMD;
  current_cmd_src = CTAP_SRC_NONE;
  cp_initialize();
  if (!reset && get_file_size(LB_FILE) >= 0) {
    if (read_attr(CTAP_CERT_FILE, SM2_ATTR, &ctap_sm2_attr, sizeof(ctap_sm2_attr)) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    DBG_MSG("CTAP initialized\n");
    return 0;
  }
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_file(DC_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(DC_FILE, DC_GENERAL_ATTR, kh_key, sizeof(CTAP_dc_general_attr)) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(DC_META_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(CTAP_CERT_FILE, NULL, 0, 0, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, kh_key, 4) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, HE_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memcpy(
      kh_key,
      (uint8_t[]){0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c},
      17);
  if (write_file(LB_FILE, kh_key, 0, 17, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memzero(kh_key, sizeof(kh_key));
  DBG_MSG("CTAP reset and initialized\n");
  return 0;
}

int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != PRI_KEY_SIZE) EXCEPT(SW_WRONG_LENGTH);
  // initialize SM2 config
  ctap_sm2_attr.enabled = 0;
  ctap_sm2_attr.curve_id = 9;  // An unused one. See https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
  ctap_sm2_attr.algo_id = -48; // An unused one. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  if (write_attr(CTAP_CERT_FILE, SM2_ATTR, &ctap_sm2_attr, sizeof(ctap_sm2_attr)) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  return write_attr(CTAP_CERT_FILE, KEY_ATTR, DATA, LC);
}

int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC > MAX_CERT_SIZE) EXCEPT(SW_WRONG_LENGTH);
  return write_file(CTAP_CERT_FILE, DATA, 0, LC, 1);
}

int ctap_read_sm2_config(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  const int ret = read_attr(CTAP_CERT_FILE, SM2_ATTR, RDATA, sizeof(ctap_sm2_attr));
  if (ret < 0) return ret;
  LL = ret;
  return 0;
}

int ctap_write_sm2_config(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != sizeof(ctap_sm2_attr)) EXCEPT(SW_WRONG_LENGTH);
  const int ret = write_attr(CTAP_CERT_FILE, SM2_ATTR, DATA, sizeof(ctap_sm2_attr));
  memcpy(&ctap_sm2_attr, DATA, sizeof(ctap_sm2_attr));
  return ret;
}

static int build_cose_key(uint8_t *data, int kty, int algo, int curve, bool has_y) {
  uint8_t buf[80];
  CborEncoder encoder, map_encoder;

  cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
  CborError ret = cbor_encoder_create_map(&encoder, &map_encoder, has_y ? 5 : 4);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_KTY);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, kty);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_ALG);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, algo);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_CRV);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, curve);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_X);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map_encoder, data, 32);
  CHECK_CBOR_RET(ret);
  if (has_y) {
    ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_Y);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map_encoder, data + 32, 32);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&encoder, &map_encoder);
  CHECK_CBOR_RET(ret);

  const int len = cbor_encoder_get_buffer_size(&encoder, buf);
  memcpy(data, buf, len);
  return len;
}

int ctap_consistency_check(void) {
  CTAP_dc_general_attr attr;
  if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (attr.pending_add || attr.pending_delete) {
    DBG_MSG("Rolling back credential operations\n");
    if (get_file_size(DC_FILE) >= ((int)attr.index + 1) * (int)sizeof(CTAP_discoverable_credential)) {
      CTAP_discoverable_credential dc;
      if (read_file(DC_FILE, &dc, attr.index * (int)sizeof(CTAP_discoverable_credential),
                    sizeof(CTAP_discoverable_credential)) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      if (!dc.deleted) {
        // delete the credential that had been written
        DBG_MSG("Delete cred at %hhu\n", attr.index);
        dc.deleted = true;
        if (write_file(DC_FILE, &dc, attr.index * (int)sizeof(CTAP_discoverable_credential),
                       sizeof(CTAP_discoverable_credential), 0) < 0)
          return CTAP2_ERR_UNHANDLED_REQUEST;
      }
    }
    // delete the meta then
    int nr_rp = get_file_size(DC_META_FILE);
    if (nr_rp < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    nr_rp /= sizeof(CTAP_rp_meta);
    for (int i = 0; i < nr_rp; ++i) {
      CTAP_rp_meta meta;
      int size = read_file(DC_META_FILE, &meta, i * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if ((meta.slots & (1ull << attr.index)) != 0) {
        DBG_MSG("Orig slot bitmap: 0x%llx\n", meta.slots);
        meta.slots &= ~(1ull << attr.index);
        DBG_MSG("New slot bitmap: 0x%llx\n", meta.slots);
        size = write_file(DC_META_FILE, &meta, i * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta), 0);
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        break;
      }
    }
    if (attr.pending_delete) attr.numbers--;

    attr.pending_add = 0;
    attr.pending_delete = 0;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  return 0;
}

uint8_t ctap_make_auth_data(uint8_t *rp_id_hash, uint8_t *buf, uint8_t flags, const uint8_t *extension,
                            size_t extension_size, size_t *len, int32_t alg_type, bool dc, uint8_t cred_protect) {
  // See https://www.w3.org/TR/webauthn/#sec-authenticator-data
  // auth data is a byte string
  // --------------------------------------------------------------------------------
  //  Name       |  Length  | Description
  // ------------|----------|---------------------------------------------------------
  //  rp_id_hash |  32      | SHA256 of rp_id, we generate it outside this function
  //  flags      |  1       | 0: UP, 2: UV, 6: AT, 7: ED
  //  sign_count |  4       | 32-bit endian number
  //  attCred    |  var     | Exist iff in authenticatorMakeCredential request
  //             |          | 16-byte aaguid
  //             |          | 2-byte key handle length
  //             |          | key handle
  //             |          | public key (in COSE_key format)
  //  extension  |  var     | Build outside
  // --------------------------------------------------------------------------------
  size_t outLen = 37; // without attCred
  CTAP_auth_data *ad = (CTAP_auth_data *)buf;
  if (*len < outLen) return CTAP2_ERR_LIMIT_EXCEEDED;

  memcpy(ad->rp_id_hash, rp_id_hash, sizeof(ad->rp_id_hash));
  ad->flags = flags;

  uint32_t ctr;
  if (increase_counter(&ctr) < 0) {
    DBG_MSG("Fail to increase the counter\n");
    return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  ad->sign_count = htobe32(ctr);

  if (flags & FLAGS_AT) {
    if (*len < outLen + sizeof(ad->at) - 1) {
      DBG_MSG("Attestation is too long\n");
      return CTAP2_ERR_LIMIT_EXCEEDED;
    }

    // If no credProtect extension was included in the request the authenticator SHOULD use the default value of 1 for
    // compatibility with CTAP2.0 platforms.
    if (cred_protect == CRED_PROTECT_ABSENT) cred_protect = CRED_PROTECT_VERIFICATION_OPTIONAL;

    memcpy(ad->at.aaguid, aaguid, sizeof(aaguid));
    ad->at.credential_id_length = htobe16(sizeof(credential_id));
    memcpy(ad->at.credential_id.rp_id_hash, rp_id_hash, sizeof(ad->at.credential_id.rp_id_hash));
    if (generate_key_handle(&ad->at.credential_id, ad->at.public_key, alg_type, (uint8_t)dc, cred_protect) < 0) {
      DBG_MSG("Fail to generate a key handle\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    int cose_key_size;
    if (alg_type == COSE_ALG_ES256) {
      cose_key_size = build_cose_key(ad->at.public_key, COSE_KEY_KTY_EC2, COSE_ALG_ES256, COSE_KEY_CRV_P256, true);
    } else if (alg_type == COSE_ALG_EDDSA) {
      cose_key_size = build_cose_key(ad->at.public_key, COSE_KEY_KTY_OKP, COSE_ALG_EDDSA, COSE_KEY_CRV_ED25519, false);
    } else if (alg_type == ctap_sm2_attr.algo_id) {
      cose_key_size =
          build_cose_key(ad->at.public_key, COSE_KEY_KTY_EC2, ctap_sm2_attr.algo_id, ctap_sm2_attr.curve_id, true);
    } else {
      DBG_MSG("Unknown algorithm type\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    outLen += sizeof(ad->at) - sizeof(ad->at.public_key) + cose_key_size;
  }
  if (flags & FLAGS_ED) {
    if (*len < outLen + extension_size) {
      DBG_MSG("Extension is too long\n");
      return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    memcpy(buf + outLen, extension, extension_size);
    outLen += extension_size;
  }
  *len = outLen;
  return 0;
}

/**
 * Encode a PublicKeyCredentialDescriptor: {id: <bytes>, type: "public-key"}
 */
static uint8_t cbor_encode_credential_id(CborEncoder *map, const credential_id *cid) {
  CborEncoder sub_map;
  int ret = cbor_encoder_create_map(map, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "id");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&sub_map, (const uint8_t *)cid, sizeof(credential_id));
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "type");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "public-key");
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(map, &sub_map);
  CHECK_CBOR_RET(ret);
  return 0;
}

/**
 * Encode a PublicKeyCredentialUserEntity.
 * @param detail If true, include name and displayName; otherwise only id.
 */
static uint8_t cbor_encode_user_entity(CborEncoder *map, const user_entity *user, bool detail) {
  CborEncoder sub_map;
  int ret = cbor_encoder_create_map(map, &sub_map, detail ? 3 : 1);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "id");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&sub_map, user->id, user->id_size);
  CHECK_CBOR_RET(ret);
  if (detail) {
    ret = cbor_encode_text_stringz(&sub_map, "name");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, user->name);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "displayName");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, user->display_name);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(map, &sub_map);
  CHECK_CBOR_RET(ret);
  return 0;
}

/**
 * Verify PIN/UV auth token for MC and GA commands.
 * Checks: token validity, permission, RP ID, user verified flag.
 * On success, associates the RP ID with the token.
 *
 * @return 0 on success, CTAP2 error code on failure.
 */
static uint8_t verify_pin_uv_auth_token(const uint8_t *client_data_hash, const uint8_t *pin_uv_auth_param,
                                        uint8_t pin_uv_auth_protocol, uint8_t permission, const uint8_t *rp_id_hash) {
  if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
  if (!cp_verify_pin_token(client_data_hash, CLIENT_DATA_HASH_SIZE, pin_uv_auth_param, pin_uv_auth_protocol)) {
    DBG_MSG("Fail to verify pin token\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (!cp_has_permission(permission)) {
    DBG_MSG("Fail to verify pin permission\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (!cp_verify_rp_id(rp_id_hash)) {
    DBG_MSG("Fail to verify pin rp id\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (!cp_get_user_verified_flag_value()) {
    DBG_MSG("userVerifiedFlagValue is false\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  cp_associate_rp_id(rp_id_hash);
  return 0;
}

static uint8_t ctap_store_discoverable_credential(const CTAP_make_credential *mc, const credential_id *cid,
                                                  CTAP_discoverable_credential *dc) {
  if (mc->options.rk != OPTION_TRUE) return 0;

  int size = get_file_size(DC_FILE);
  if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  int n_dc = size / (int)sizeof(CTAP_discoverable_credential), pos, first_deleted = MAX_DC_NUM;
  for (pos = 0; pos != n_dc; ++pos) {
    if (read_file(DC_FILE, dc, pos * (int)sizeof(CTAP_discoverable_credential), sizeof(CTAP_discoverable_credential)) <
        0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (dc->deleted) {
      if (first_deleted == MAX_DC_NUM) first_deleted = pos;
      continue;
    }
    if (memcmp_s(mc->rp_id_hash, dc->credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
        mc->user.id_size == dc->user.id_size && memcmp_s(mc->user.id, dc->user.id, mc->user.id_size) == 0)
      break;
  }
  if (pos == n_dc && first_deleted != MAX_DC_NUM) pos = first_deleted;
  if (pos >= MAX_DC_NUM) return CTAP2_ERR_KEY_STORE_FULL;

  memcpy(&dc->credential_id, cid, sizeof(*cid));
  memcpy(&dc->user, &mc->user, sizeof(user_entity));
  dc->has_large_blob_key = mc->ext_large_blob_key;
  dc->cred_blob_len = 0;
  if (mc->ext_has_cred_blob && mc->ext_cred_blob_len <= MAX_CRED_BLOB_LENGTH) {
    dc->cred_blob_len = mc->ext_cred_blob_len;
    memcpy(dc->cred_blob, mc->ext_cred_blob, mc->ext_cred_blob_len);
  }
  dc->deleted = false;

  CTAP_dc_general_attr attr;
  if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  attr.pending_add = 1;
  attr.index = (uint8_t)pos;
  if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(DC_FILE, dc, pos * (int)sizeof(CTAP_discoverable_credential), sizeof(CTAP_discoverable_credential),
                 0) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;

  size = get_file_size(DC_META_FILE);
  if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  int n_rp = size / (int)sizeof(CTAP_rp_meta), meta_pos;
  CTAP_rp_meta meta;
  first_deleted = MAX_DC_NUM;
  for (meta_pos = 0; meta_pos != n_rp; ++meta_pos) {
    size = read_file(DC_META_FILE, &meta, meta_pos * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (meta.slots == 0) {
      if (first_deleted == MAX_DC_NUM) first_deleted = meta_pos;
      continue;
    }
    if (memcmp_s(mc->rp_id_hash, meta.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) break;
  }
  if (meta_pos == n_rp) {
    meta.slots = 0;
    if (first_deleted != MAX_DC_NUM) meta_pos = first_deleted;
  }
  memcpy(meta.rp_id_hash, mc->rp_id_hash, SHA256_DIGEST_LENGTH);
  memcpy(meta.rp_id, mc->rp_id, MAX_STORED_RPID_LENGTH);
  meta.rp_id_len = mc->rp_id_len;
  meta.slots |= 1ull << pos;
  if (write_file(DC_META_FILE, &meta, meta_pos * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta), 0) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  attr.pending_add = 0;
  ++attr.numbers;
  if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  return 0;
}

static uint8_t ctap_prepare_make_credential_response(CborEncoder *encoder, CTAP_make_credential *mc, bool uv,
                                                     const uint8_t *extension, size_t extension_size) {
  CTAP_mldsa_stream_state *state = &mldsa_stream_state;
  credential_id cid;
  CTAP_discoverable_credential dc = {0};
  uint8_t flags = FLAGS_AT | (extension_size > 0 ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | FLAGS_UP;
  uint8_t cred_protect =
      mc->ext_cred_protect == CRED_PROTECT_ABSENT ? CRED_PROTECT_VERIFICATION_OPTIONAL : mc->ext_cred_protect;
  uint8_t data_buf[sizeof(CTAP_auth_data)];
  bool mldsa = mc->alg_type == COSE_ALG_ML_DSA_65;
  uint8_t *prefix = mldsa ? state->prefix : (stream_make_credential_response ? stream_resp_base : encoder->data.ptr);
  uint8_t *auth_data_start;
  uint8_t *p = prefix;
  sha256_ctx_t sha256;
  size_t cert_prefix_len;
  size_t sig_len;
  int cert_len;

  if (mldsa && !stream_make_credential_response) return CTAP2_ERR_LIMIT_EXCEEDED;
  if (stream_make_credential_response) *p++ = 0;
  if (mldsa) {
    memset(state, 0, sizeof(*state));
    state->stage = global_buffer;
  }

  if (cbor_put_uint(&p, 3 + (mc->ext_large_blob_key ? 1 : 0), 0xA0) < 0 || cbor_put_int(&p, MC_RESP_FMT) < 0 ||
      cbor_put_text(&p, "packed") < 0 || cbor_put_int(&p, MC_RESP_AUTH_DATA) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;

  sha256_init(&sha256);
  if (mldsa) {
    uint32_t ctr;
    const size_t auth_len =
        37 + AAGUID_SIZE + sizeof(uint16_t) + sizeof(credential_id) + 10 + MLDSA_PK_BYTES + extension_size;
    memcpy(cid.rp_id_hash, mc->rp_id_hash, sizeof(cid.rp_id_hash));
    if (generate_key_handle(&cid, state->seed, mc->alg_type, mc->options.rk == OPTION_TRUE, cred_protect) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (increase_counter(&ctr) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    uint8_t err = ctap_store_discoverable_credential(mc, &cid, &dc);
    if (err) return err;

    if (cbor_put_bytes_header(&p, auth_len) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    auth_data_start = p;
    memcpy(p, mc->rp_id_hash, SHA256_DIGEST_LENGTH);
    p += SHA256_DIGEST_LENGTH;
    *p++ = flags;
    ctr = htobe32(ctr);
    memcpy(p, &ctr, sizeof(ctr));
    p += sizeof(ctr);
    memcpy(p, aaguid, AAGUID_SIZE);
    p += AAGUID_SIZE;
    *p++ = HI(sizeof(credential_id));
    *p++ = LO(sizeof(credential_id));
    memcpy(p, &cid, sizeof(cid));
    p += sizeof(cid);
    if (cbor_put_mldsa65_cose_prefix(&p) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    state->prefix_len = (size_t)(p - state->prefix);
    sha256_update(&sha256, auth_data_start, p - auth_data_start);

    memset(&state->keygen, 0, sizeof(state->keygen));
    memcpy(state->keygen.seed, state->seed, PRI_KEY_SIZE);
    do {
      KEEPALIVE();
      int pk_len = ml_dsa_65_keygen_streaming(global_buffer, APDU_BUFFER_SIZE, &state->keygen, NULL);
      if (pk_len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (pk_len != 0) sha256_update(&sha256, global_buffer, (size_t)pk_len);
    } while (state->keygen.phase != 0);
    if (extension_size != 0) sha256_update(&sha256, extension, extension_size);
  } else {
    size_t auth_data_len = sizeof(data_buf);
    int ret = ctap_make_auth_data(mc->rp_id_hash, data_buf, flags, extension, extension_size, &auth_data_len,
                                  mc->alg_type, mc->options.rk == OPTION_TRUE, mc->ext_cred_protect);
    if (ret != 0) return ret;
    if (cbor_put_bytes_header(&p, auth_data_len) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(p, data_buf, auth_data_len);
    p += auth_data_len;

    const size_t cred_id_off = 37 + AAGUID_SIZE + sizeof(uint16_t);
    memcpy(&cid, data_buf + cred_id_off, sizeof(cid));
    if (mc->options.rk == OPTION_TRUE) {
      uint8_t err = ctap_store_discoverable_credential(mc, (credential_id *)(data_buf + cred_id_off), &dc);
      if (err) return err;
    }
    sha256_update(&sha256, data_buf, auth_data_len);
  }
  sha256_update(&sha256, mc->client_data_hash, sizeof(mc->client_data_hash));
  sha256_final(&sha256, data_buf);
  sig_len = sign_with_device_key(data_buf, PRIVATE_KEY_LENGTH[SECP256R1], data_buf);
  if (!sig_len) return CTAP2_ERR_UNHANDLED_REQUEST;

  uint8_t *suffix = mldsa ? state->suffix : p;
  uint8_t *q = suffix;
  if (mldsa && extension_size != 0) {
    memcpy(q, extension, extension_size);
    q += extension_size;
  }
  if (cbor_put_int(&q, MC_RESP_ATT_STMT) < 0 || cbor_put_uint(&q, 3, 0xA0) < 0 || cbor_put_text(&q, "alg") < 0 ||
      cbor_put_int(&q, COSE_ALG_ES256) < 0 || cbor_put_text(&q, "sig") < 0 || cbor_put_bytes_header(&q, sig_len) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  memcpy(q, data_buf, sig_len);
  q += sig_len;
  if (cbor_put_text(&q, "x5c") < 0 || cbor_put_uint(&q, 1, 0x80) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  cert_len = get_file_size(CTAP_CERT_FILE);
  if (cert_len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (cbor_put_bytes_header(&q, (size_t)cert_len) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  cert_prefix_len = (size_t)(q - suffix);

  if (!stream_make_credential_response) {
    if (get_cert(q) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    q += cert_len;
  }

  uint8_t *tail = q;
  if (mc->ext_large_blob_key) {
    uint8_t large_blob_key[LARGE_BLOB_KEY_SIZE];
    if (make_large_blob_key(cid.nonce, large_blob_key) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cbor_put_int(&q, MC_RESP_LARGE_BLOB_KEY) < 0 || cbor_put_bytes_header(&q, LARGE_BLOB_KEY_SIZE) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(q, large_blob_key, LARGE_BLOB_KEY_SIZE);
    q += LARGE_BLOB_KEY_SIZE;
    memzero(large_blob_key, sizeof(large_blob_key));
  }

  if (mldsa) {
    state->suffix_len = (size_t)(q - state->suffix);
    state->kind = CTAP_MLDSA_STREAM_PK;
    memset(&state->keygen, 0, sizeof(state->keygen));
    state->stage_len = 0;
    state->stage_off = 0;
    state->total_len = state->prefix_len + MLDSA_PK_BYTES + state->suffix_len + (size_t)cert_len;
  }

  if (stream_make_credential_response) {
    const size_t prefix_len = mldsa ? state->prefix_len : (size_t)(suffix + cert_prefix_len - prefix);
    const size_t tail_len = mldsa ? state->suffix_len - cert_prefix_len : (size_t)(q - tail);
    if (ctap_make_credential_stream_add_mem(prefix, prefix_len) < 0 ||
        (mldsa && ctap_make_credential_stream_add_mldsa(state, MLDSA_PK_BYTES) < 0) ||
        (mldsa && ctap_make_credential_stream_add_mem(state->suffix, cert_prefix_len) < 0) ||
        ctap_make_credential_stream_add_file(CTAP_CERT_FILE, 0, (size_t)cert_len) < 0 ||
        ctap_make_credential_stream_add_mem(tail, tail_len) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (mldsa) {
      DBG_MSG("makeCredential stream prefix=%zu mldsa-pk=%u suffix=%zu cert=%d total=%zu\n", state->prefix_len,
              MLDSA_PK_BYTES, state->suffix_len, cert_len, mc_stream_state.total_len);
    } else {
      DBG_MSG("makeCredential stream prefix=%zu cert=%d suffix=%zu total=%zu\n", prefix_len, cert_len, tail_len,
              mc_stream_state.total_len);
    }
  } else {
    encoder->data.ptr = q;
  }

  return 0;
}

static uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg
  uint8_t data_buf[sizeof(CTAP_auth_data)];
  CborParser parser;
  CTAP_make_credential mc;

  int ret = parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);

  ret = ctap_consistency_check();
  CHECK_PARSER_RET(ret);
  KEEPALIVE();

  // 1. If authenticator supports clientPin features and the platform sends a zero length pin_uv_auth_param
  if ((mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && mc.pin_uv_auth_param_len == 0) {
    // a. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    // b. If the user declines permission, or the operation times out, then end the operation by returning
    //    CTAP2_ERR_OPERATION_DENIED.
    WAIT(CTAP2_ERR_OPERATION_DENIED);
    // c. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
    //    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    if (has_pin())
      return CTAP2_ERR_PIN_INVALID;
    else
      return CTAP2_ERR_PIN_NOT_SET;
  }

  // 2. If the pin_uv_auth_param parameter is present
  //   a. If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
  //     > This has been processed when parsing.
  //   b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
  if ((mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && !(mc.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
    DBG_MSG("Missing required pin_uv_auth_protocol\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }
  // 3. Validate pubKeyCredParams with the following steps
  //    > This has been processed when parsing.

  // 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as
  // false.
  bool uv = false; // up is always true, see 14.c

  // 5. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (mc.options.uv == OPTION_ABSENT) mc.options.uv = OPTION_FALSE;
  //    b. If the pin_uv_auth_param is present, let the "uv" option be treated as being present with the value false.
  if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) mc.options.uv = OPTION_FALSE;
  //    c. If the "uv" option is true then
  if (mc.options.uv == OPTION_TRUE) {
    //     1) If the authenticator does not support a built-in user verification method end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
    DBG_MSG("Rule 5-c-1 not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
    //     2) [N/A] If the built-in user verification method has not yet been enabled, end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
  }
  //    d. If the "rk" option is present then: DO NOTHING
  //    e. Else: (the "rk" option is absent): Let the "rk" option be treated as being present with the value false.
  if (mc.options.rk == OPTION_ABSENT) mc.options.rk = OPTION_FALSE;
  //    f. If the "up" option is present then:
  //       If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
  if (mc.options.up == OPTION_FALSE) {
    DBG_MSG("Rule 5-f not satisfied\n");
    return CTAP2_ERR_INVALID_OPTION;
  }
  //    g. If the "up" option is absent, let the "up" option be treated as being present with the value true
  mc.options.up = OPTION_TRUE;

  // 6. [N/A] If the alwaysUv option ID is present and true

  // 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response
  //    If the following statements are all true:
  //    a) The authenticator is protected by some form of user verification.
  //    b) [ALWAYS TRUE] The "uv" option is set to false.
  //    c) The pin_uv_auth_param parameter is not present.
  //    d) The "rk" option is present and set to true.
  if (has_pin() /* a) */ && (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0 /* c) */ &&
      mc.options.rk == OPTION_TRUE) {
    // If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    // end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    DBG_MSG("Rule 7 not satisfied\n");
    return CTAP2_ERR_PUAT_REQUIRED;
    // [N/A] Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
  }

  // 8. [N/A] Else (the makeCredUvNotRqd option ID is present with the value false or is absent)

  // 9. [N/A] If the enterpriseAttestation parameter is present

  // 10. If the following statements are all true
  //     a) "rk" and "uv" [ALWAYS TRUE] options are both set to false or omitted.
  //     b) [ALWAYS TRUE] the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value
  //     true. c) the pin_uv_auth_param parameter is not present. Then go to Step 12.
  if (mc.options.rk == OPTION_FALSE && (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0) {
    DBG_MSG("Rule 10 satisfied, go to Step 12\n");
    goto step12;
  }

  // 11. If the authenticator is protected by some form of user verification, then:
  if (has_pin()) {
    //   11.1 If pin_uv_auth_param parameter is present (implying the "uv" option is false (see Step 5)):
    if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
      uint8_t err = verify_pin_uv_auth_token(mc.client_data_hash, mc.pin_uv_auth_param, mc.pin_uv_auth_protocol,
                                             CP_PERMISSION_MC, mc.rp_id_hash);
      if (err) return err;
      uv = true;
      DBG_MSG("PIN verified\n");
    }
    //   11.2 [N/A] If the "uv" option is present and set to true
  }

step12:
  // 12. If the exclude_list parameter is present and contains a credential ID created by this authenticator,
  //     that is bound to the specified rp.id:
  if (mc.exclude_list_size > 0) {
    for (size_t i = 0; i < mc.exclude_list_size; ++i) {
      ecc_key_t key;
      parse_credential_descriptor(&mc.exclude_list, data_buf); // save credential id in data_buf
      credential_id *kh = (credential_id *)data_buf;
      // compare rp_id first
      if (memcmp_s(kh->rp_id_hash, mc.rp_id_hash, sizeof(kh->rp_id_hash)) != 0) goto next_exclude_list;
      // then verify key handle and get private key in rp_id_hash
      ret = verify_key_handle(kh, &key);
      memzero(&key, sizeof(key));
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (ret == 0) {
        DBG_MSG("Exclude ID found\n");
        // a) If the credential's credProtect value is not userVerificationRequired
        if (kh->nonce[CREDENTIAL_NONCE_CP_POS] != CRED_PROTECT_VERIFICATION_REQUIRED ||
            // b) Else (implying the credential's credProtect value is userVerificationRequired)
            //    AND If the "uv" bit is true in the response:
            (kh->nonce[CREDENTIAL_NONCE_CP_POS] == CRED_PROTECT_VERIFICATION_REQUIRED && uv)) {

          //    i. Let userPresentFlagValue be false.
          bool userPresentFlagValue = false;
          //    ii. If the pinUvAuthParam parameter is present then let userPresentFlagValue be the result of calling
          //        getUserPresentFlagValue().
          if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) userPresentFlagValue = cp_get_user_present_flag_value();
          //    iii. [N/A] Else, if evidence of user interaction was provided as part of Step 11 let
          //    userPresentFlagValue be true. iv. If userPresentFlagValue is false, then:
          //        (1) Wait for user presence.
          //        (2) Regardless of whether user presence is obtained or the authenticator times out,
          //            terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
          if (!userPresentFlagValue) WAIT(CTAP2_ERR_CREDENTIAL_EXCLUDED);
          //    v. Else, (implying userPresentFlagValue is true) terminate this procedure and return
          //    CTAP2_ERR_CREDENTIAL_EXCLUDED.
          return CTAP2_ERR_CREDENTIAL_EXCLUDED;

          // c) Else (implying user verification was not collected in Step 11),
          //    remove the credential from the excludeList and continue parsing the rest of the list.
        } else {
          DBG_MSG("Ignore this Exclude ID\n");
        }
      }
    next_exclude_list:
      ret = cbor_value_advance(&mc.exclude_list);
      CHECK_CBOR_RET(ret);
    }
  }

  // 13. [N/A] If evidence of user interaction was provided as part of Step 11

  // 14. [ALWAYS TRUE] If the "up" option is set to true
  //     a) If the pin_uv_auth_param parameter is present then:
  if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
    if (!cp_get_user_present_flag_value()) {
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
  } else {
    //   b) Else (implying the pin_uv_auth_param parameter is not present)
    //     1. [ALWAYS TRUE] If the "up" bit is false in the response :
    WAIT(CTAP2_ERR_OPERATION_DENIED);
  }
  //     c) [N/A] Set the "up" bit to true in the response
  //     d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  CborEncoder map;
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  size_t extension_size = 0;
  // 15. If the extensions parameter is present:
  uint8_t extension_map_items = (mc.ext_hmac_secret ? 1 : 0) +
                                // largeBlobKey has no outputs here
                                (mc.ext_cred_protect != CRED_PROTECT_ABSENT ? 1 : 0) + (mc.ext_has_cred_blob ? 1 : 0);
  if (extension_map_items > 0) {
    CborEncoder extension_encoder;
    cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
    ret = cbor_encoder_create_map(&extension_encoder, &map, extension_map_items);
    CHECK_CBOR_RET(ret);

    if (mc.ext_has_cred_blob) {
      bool accepted = false;
      if (mc.ext_cred_blob_len <= MAX_CRED_BLOB_LENGTH && mc.options.rk == OPTION_TRUE) {
        accepted = true;
      }
      ret = cbor_encode_text_stringz(&map, "credBlob");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_boolean(&map, accepted);
      CHECK_CBOR_RET(ret);
    }
    if (mc.ext_cred_protect != CRED_PROTECT_ABSENT) {
      ret = cbor_encode_text_stringz(&map, "credProtect");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, mc.ext_cred_protect);
      CHECK_CBOR_RET(ret);
    }
    if (mc.ext_hmac_secret) {
      ret = cbor_encode_text_stringz(&map, "hmac-secret");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_boolean(&map, true);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&extension_encoder, &map);
    CHECK_CBOR_RET(ret);
    extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
    DBG_MSG("extension_size=%zu\n", extension_size);
  }
  if (mc.ext_large_blob_key) {
    if (mc.options.rk != OPTION_TRUE) {
      DBG_MSG("largeBlobKey requires rk\n");
      return CTAP2_ERR_INVALID_OPTION;
    }
    // Generate key in Step 17
  }

  return ctap_prepare_make_credential_response(encoder, &mc, uv, extension_buffer, extension_size);
}

static uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *params, size_t len, bool in_get_next_assertion) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
  static CTAP_get_assertion ga;
  static uint8_t credential_list[MAX_DC_NUM], number_of_credentials, credential_counter;
  static bool uv, up, user_details;
  static uint32_t timer;

  CTAP_discoverable_credential dc = {0}; // We use dc to store the selected credential
  uint8_t data_buf[sizeof(CTAP_auth_data) + CLIENT_DATA_HASH_SIZE];
  ecc_key_t key; // TODO: cleanup
  CborParser parser;
  int ret;

  if (!in_get_next_assertion) {
    credential_counter = 0;
    ret = ctap_consistency_check();
    CHECK_PARSER_RET(ret);
  } else {
    // GET_NEXT_ASSERTION
    // 1. If authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
    if (last_cmd != CTAP_GET_ASSERTION && last_cmd != CTAP_GET_NEXT_ASSERTION) return CTAP2_ERR_NOT_ALLOWED;
    // 2. If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
    if (credential_counter >= number_of_credentials) return CTAP2_ERR_NOT_ALLOWED;
    // 3. If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than
    //    30 seconds, discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
    //    This step is OPTIONAL if transport is done over NFC.
    if (device_get_tick() - timer > 30000) return CTAP2_ERR_NOT_ALLOWED;
    // 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
    // 5. Update the response to include the selected credential's publicKeyCredentialUserEntity information.
    //    User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be
    //    returned if user verification was not done by the authenticator in the original authenticatorGetAssertion
    //    call.
    // 6. Sign the client_data_hash along with authData with the selected credential.
    goto step7;
    // 7. Reset the timer. This step is OPTIONAL if transport is done over NFC.
    // 8. Increment credentialCounter.
    // > Process at the end of this function.
  }
  ret = parse_get_assertion(&parser, &ga, params, len);
  CHECK_PARSER_RET(ret);
  KEEPALIVE();

  // 1. If authenticator supports clientPin features and the platform sends a zero length pin_uv_auth_param
  if ((ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && ga.pin_uv_auth_param_len == 0) {
    // a. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    // b. If the user declines permission, or the operation times out, then end the operation by returning
    //    CTAP2_ERR_OPERATION_DENIED.
    WAIT(CTAP2_ERR_OPERATION_DENIED);
    // c. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
    //    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    if (has_pin())
      return CTAP2_ERR_PIN_INVALID;
    else
      return CTAP2_ERR_PIN_NOT_SET;
  }

  // 2. If the pin_uv_auth_param parameter is present
  //   a. If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
  //     > This has been processed when parsing.
  //   b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
  if ((ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && !(ga.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
    DBG_MSG("Missing required pin_uv_auth_protocol\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }

  // 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as
  // false.
  uv = false;
  up = false;

  // 4. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (ga.options.uv == OPTION_ABSENT) ga.options.uv = OPTION_FALSE;
  //    b. If the pin_uv_auth_param is present, let the "uv" option be treated as being present with the value false.
  if (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) ga.options.uv = OPTION_FALSE;
  //    c. If the "uv" option is true then
  if (ga.options.uv == OPTION_TRUE) {
    //     1) If the authenticator does not support a built-in user verification method end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
    DBG_MSG("Rule 4-c-1 not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
    //     2) [N/A] If the built-in user verification method has not yet been enabled, end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
  }
  //    d. If the "rk" option is present then: Return CTAP2_ERR_UNSUPPORTED_OPTION.
  if (ga.options.rk != OPTION_ABSENT) {
    DBG_MSG("Rule 4-d not satisfied.\n");
    return CTAP2_ERR_UNSUPPORTED_OPTION;
  }
  //    e. If the "up" option is not present then: Let the "up" option be treated as being present with the value true.
  if (ga.options.up == OPTION_ABSENT) ga.options.up = OPTION_TRUE;

  // 5. [N/A] If the alwaysUv option ID is present and true and the "up" option is present and true

  // 6. If authenticator is protected by some form of user verification, then:
  //    6.2 [N/A] If the "uv" option is present and set to true
  //    6.1 If pin_uv_auth_param parameter is present
  if (has_pin() && (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
    uint8_t err = verify_pin_uv_auth_token(ga.client_data_hash, ga.pin_uv_auth_param, ga.pin_uv_auth_protocol,
                                           CP_PERMISSION_GA, ga.rp_id_hash);
    if (err) return err;
    uv = true;
  }

step7:
  // 7. Locate all credentials that are eligible for retrieval under the specified criteria
  //    a) If the allow_list parameter is present and is non-empty, locate all denoted credentials created by this
  //       authenticator and bound to the specified rp_id.
  //    b) If an allow_list is not present, locate all discoverable credentials that are created by this authenticator
  //       and bound to the specified rp_id.
  //    c) Create an applicable credentials list populated with the located credentials.
  //    d) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationRequired, and the "uv" bit is false in the response, remove that credential from the
  //       applicable credentials list.
  //    e) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationOptionalWithCredentialIDList and there is no allow_list passed by the client and the "uv"
  //       bit is false in the response, remove that credential from the applicable credentials list.
  //    f) If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
  //    g) Let numberOfCredentials be the number of applicable credentials found.
  // NOTE: only one credential is used as stated in Step 11 & 12; therefore, we select that credential according to
  //       Step 11 & 12:
  // 11. If the allow_list parameter is present:
  //     Select any credential from the applicable credentials list.
  //     Delete the numberOfCredentials member.
  // 12. If allow_list is not present:
  //     a) If numberOfCredentials is one: Select that credential.
  //     b) If numberOfCredentials is more than one:
  //        1) Order the credentials in the applicable credentials list by the time when they were created in
  //           reverse order. (I.e. the first credential is the most recently created.)
  //        2）If the authenticator does not have a display:
  //           i. Remember the authenticatorGetAssertion parameters.
  //           ii. Create a credential counter (credentialCounter) and set it to 1. This counter signifies the next
  //               credential to be returned by the authenticator, assuming zero-based indexing.
  //           iii. Start a timer. This is used during authenticatorGetNextAssertion command. This step is OPTIONAL
  //                if transport is done over NFC.
  //           iv. Select the first credential.
  //        3) [N/A] If authenticator has a display and at least one of the "uv" and "up" options is true.
  //    c) Update the response to include the selected credential's publicKeyCredentialUserEntity information.
  //       User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity
  //       MUST NOT be returned if user verification is not done by the authenticator.
  if (ga.allow_list_size > 0) { // Step 11
    size_t i;
    for (i = 0; i < ga.allow_list_size; ++i) {
      parse_credential_descriptor(&ga.allow_list, (uint8_t *)&dc.credential_id);
      // compare the rp_id first
      if (memcmp_s(dc.credential_id.rp_id_hash, ga.rp_id_hash, sizeof(dc.credential_id.rp_id_hash)) != 0) goto next;
      // then verify the key handle and get private key
      int err = verify_key_handle(&dc.credential_id, &key);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) {
        // Skip the credential which is protected
        if (!check_credential_protect_requirements(&dc.credential_id, true, uv)) goto next;
        if (dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS]) { // Verify if it's a valid dc.
          memcpy(data_buf, dc.credential_id.nonce,
                 sizeof(dc.credential_id.nonce)); // use data_buf to store the nonce temporarily
          int size = get_file_size(DC_FILE);
          if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
          int n_dc = (int)(size / sizeof(CTAP_discoverable_credential));
          bool found = false;
          DBG_MSG("%d discoverable credentials\n", n_dc);
          for (int j = 0; j < n_dc; ++j) {
            if (read_file(DC_FILE, &dc, j * (int)sizeof(CTAP_discoverable_credential),
                          sizeof(CTAP_discoverable_credential)) < 0)
              return CTAP2_ERR_UNHANDLED_REQUEST;
            if (dc.deleted) {
              DBG_MSG("Skipped DC at %d\n", j);
              continue;
            }
            if (memcmp_s(ga.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
                memcmp_s(data_buf, dc.credential_id.nonce, sizeof(dc.credential_id.nonce)) == 0) {
              found = true;
              break;
            }
          }
          DBG_MSG("matching credential_id%s found\n", (found ? "" : " not"));
          if (found) break;
          // if (!found) return CTAP2_ERR_NO_CREDENTIALS;
        } else { // not DC
          break; // Step 11: Select any credential from the applicable credentials list.
        }
      }
    next:
      ret = cbor_value_advance(&ga.allow_list);
      CHECK_CBOR_RET(ret);
    }
    // 7-f
    if (i == ga.allow_list_size) {
      DBG_MSG("no valid credential found in the allow list\n");
      return CTAP2_ERR_NO_CREDENTIALS;
    }
    number_of_credentials = 1;
  } else { // Step 12
    int size;
    if (credential_counter == 0) {
      size = get_file_size(DC_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      int n_dc = (int)(size / sizeof(CTAP_discoverable_credential));
      number_of_credentials = 0;
      for (int i = n_dc - 1; i >= 0; --i) { // 12-b-1
        if (read_file(DC_FILE, &dc, i * (int)sizeof(CTAP_discoverable_credential),
                      sizeof(CTAP_discoverable_credential)) < 0)
          return CTAP2_ERR_UNHANDLED_REQUEST;
        if (dc.deleted) {
          DBG_MSG("Skipped DC at %d\n", i);
          continue;
        }
        // Skip the credential which is protected
        if (!check_credential_protect_requirements(&dc.credential_id, false, uv)) continue;
        if (memcmp_s(ga.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0)
          credential_list[number_of_credentials++] = i;
      }
      // 7-f
      if (number_of_credentials == 0) return CTAP2_ERR_NO_CREDENTIALS;
    }
    // fetch dc and get private key
    if (read_file(DC_FILE, &dc, credential_list[credential_counter] * (int)sizeof(CTAP_discoverable_credential),
                  sizeof(CTAP_discoverable_credential)) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (verify_key_handle(&dc.credential_id, &key) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // For single account per RP case, authenticator returns "id" field to the platform which will be returned to the
  // [WebAuthn] layer. For multiple accounts per RP case, where the authenticator does not have a display, authenticator
  // returns "id" as well as other fields to the platform. User identifiable information (name, DisplayName, icon) MUST
  // NOT be returned if user verification is not done by the authenticator.
  user_details = uv && number_of_credentials > 1;

  // 8. [N/A] If evidence of user interaction was provided as part of Step 6.2
  // 9. If the "up" option is set to true or not present:
  //    Note: This step is skipped in authenticatorGetNextAssertion
  if (credential_counter == 0 && ga.options.up == OPTION_TRUE) {
    //    a) If the pin_uv_auth_param parameter is present then:
    if (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
      if (!cp_get_user_present_flag_value()) {
        WAIT(CTAP2_ERR_OPERATION_DENIED);
      }
    } else {
      //    b) Else (implying the pin_uv_auth_param parameter is not present):
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
    //    c) Set the "up" bit to true in the response.
    up = true;
    //    d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    cp_clear_user_present_flag();
    cp_clear_user_verified_flag();
    cp_clear_pin_uv_auth_token_permissions_except_lbw();
  }

  DBG_MSG("Credential id: ");
  PRINT_HEX((const uint8_t *)&dc.credential_id, sizeof(dc.credential_id));

  // 10. If the extensions parameter is present:
  //     a) Process any extensions that this authenticator supports, ignoring any that it does not support.
  //     b) Authenticator extension outputs generated by the authenticator extension processing are returned to the
  //        authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to, or a subset
  //        of, the keys of the authenticator extension inputs map.

  // Process credProtect extension
  if (!check_credential_protect_requirements(&dc.credential_id, ga.allow_list_size > 0, uv))
    return CTAP2_ERR_NO_CREDENTIALS;

  CborEncoder map;
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  size_t extension_size = 0;
  uint8_t extension_map_items = (ga.ext_cred_blob ? 1 : 0) +
                                // largeBlobKey has no outputs here
                                ((ga.parsed_params & PARAM_HMAC_SECRET) ? 1 : 0);
  if (extension_map_items > 0) {
    CborEncoder extension_encoder;
    // build extensions
    cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
    ret = cbor_encoder_create_map(&extension_encoder, &map, extension_map_items);
    CHECK_CBOR_RET(ret);

    // Process credBlob extension
    if (ga.ext_cred_blob) {
      ret = cbor_encode_text_stringz(&map, "credBlob");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, dc.cred_blob, dc.cred_blob_len);
      CHECK_CBOR_RET(ret);
    }

    // Process hmac-secret extension
    if (ga.parsed_params & PARAM_HMAC_SECRET) {
      if (credential_counter == 0) {
        // If "up" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION.
        if (!up) return CTAP2_ERR_UNSUPPORTED_OPTION;
        ret = cp_decapsulate(ga.ext_hmac_secret_key_agreement, ga.ext_hmac_secret_pin_protocol);
        CHECK_PARSER_RET(ret);
        DBG_MSG("Shared secret: ");
        PRINT_HEX(ga.ext_hmac_secret_key_agreement,
                  ga.ext_hmac_secret_pin_protocol == 2 ? SHARED_SECRET_SIZE_P2 : SHARED_SECRET_SIZE_P1);
        if (!cp_verify(ga.ext_hmac_secret_key_agreement, SHARED_SECRET_SIZE_HMAC, ga.ext_hmac_secret_salt_enc,
                       ga.ext_hmac_secret_salt_enc_len, ga.ext_hmac_secret_salt_auth,
                       ga.ext_hmac_secret_pin_protocol)) {
          ERR_MSG("Hmac verification failed\n");
          return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (cp_decrypt(ga.ext_hmac_secret_key_agreement, ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_salt_enc_len,
                       ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_pin_protocol) != 0) {
          ERR_MSG("Hmac decryption failed\n");
          return CTAP2_ERR_UNHANDLED_REQUEST;
        }
      }
      uint8_t hmac_secret_output[HMAC_SECRET_SALT_IV_SIZE + HMAC_SECRET_SALT_SIZE];
      DBG_MSG("hmac-secret-salt: ");
      PRINT_HEX(ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_pin_protocol == 1
                                                 ? ga.ext_hmac_secret_salt_enc_len
                                                 : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE);
      ret = make_hmac_secret_output(dc.credential_id.nonce, ga.ext_hmac_secret_salt_enc,
                                    ga.ext_hmac_secret_pin_protocol == 1
                                        ? ga.ext_hmac_secret_salt_enc_len
                                        : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE,
                                    hmac_secret_output, uv);
      CHECK_PARSER_RET(ret);
      DBG_MSG("hmac-secret %s UV (plain): ", uv ? "with" : "without");
      PRINT_HEX(hmac_secret_output, ga.ext_hmac_secret_pin_protocol == 1
                                        ? ga.ext_hmac_secret_salt_enc_len
                                        : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE);
      if (cp_encrypt(ga.ext_hmac_secret_key_agreement, hmac_secret_output,
                     ga.ext_hmac_secret_pin_protocol == 1 ? ga.ext_hmac_secret_salt_enc_len
                                                          : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE,
                     hmac_secret_output, ga.ext_hmac_secret_pin_protocol) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      DBG_MSG("hmac-secret output: ");
      PRINT_HEX(hmac_secret_output, ga.ext_hmac_secret_salt_enc_len);
      if (credential_counter + 1 == number_of_credentials) { // encryption key will not be used any more
        memzero(ga.ext_hmac_secret_key_agreement, sizeof(ga.ext_hmac_secret_key_agreement));
      }

      ret = cbor_encode_text_stringz(&map, "hmac-secret");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, hmac_secret_output, ga.ext_hmac_secret_salt_enc_len);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&extension_encoder, &map);
    CHECK_CBOR_RET(ret);
    extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
    DBG_MSG("extension_size=%zu\n", extension_size);
  }

  // 13. Sign the client_data_hash along with authData with the selected credential.
  bool has_user = dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS];
  bool has_multiple_credentials = ga.allow_list_size == 0 && credential_counter == 0 && number_of_credentials > 1;
  uint8_t map_items = 3;
  if (has_user) ++map_items; // user. For discoverable credentials on FIDO devices, at least user "id" is mandatory.
  if (has_multiple_credentials) ++map_items; // numberOfCredentials
  if (dc.has_large_blob_key) ++map_items;    // largeBlobKey
  uint8_t *stream_resp_start = encoder->data.ptr;
  ret = cbor_encoder_create_map(encoder, &map, map_items);
  CHECK_CBOR_RET(ret);

  // build credential id
  ret = cbor_encode_int(&map, GA_RESP_CREDENTIAL);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_credential_id(&map, &dc.credential_id);
  CHECK_CBOR_RET(ret);

  // auth data
  len = sizeof(data_buf);
  uint8_t flags = (extension_size > 0 ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | (up ? FLAGS_UP : 0);
  ret = ctap_make_auth_data(ga.rp_id_hash, data_buf, flags, extension_buffer, extension_size, &len,
                            dc.credential_id.alg_type, has_user, dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS]);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, MC_RESP_AUTH_DATA);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // signature
  ret = cbor_encode_int(&map, GA_RESP_SIGNATURE);
  CHECK_CBOR_RET(ret);
  if (dc.credential_id.alg_type == COSE_ALG_ML_DSA_65) {
    CTAP_mldsa_stream_state *state = &mldsa_stream_state;
    uint8_t *p;
    memset(state, 0, sizeof(*state));
    state->stage = global_buffer;
    memcpy(state->seed, key.pri, PRI_KEY_SIZE);
    p = state->prefix;
    *p++ = 0;
    memcpy(p, stream_resp_start, map.data.ptr - stream_resp_start);
    p += map.data.ptr - stream_resp_start;
    cbor_put_bytes_header(&p, MLDSA_SIG_BYTES);
    state->prefix_len = (size_t)(p - state->prefix);
    if (ctap_mldsa65_tr_from_seed(state->seed, state->tr) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(data_buf + len, ga.client_data_hash, CLIENT_DATA_HASH_SIZE);
    memcpy(state->msg, data_buf, len + CLIENT_DATA_HASH_SIZE);
    state->msg_len = len + CLIENT_DATA_HASH_SIZE;

    CborEncoder suffix_encoder;
    cbor_encoder_init(&suffix_encoder, state->suffix, sizeof(state->suffix), 0);
    if (has_user) {
      ret = cbor_encode_int(&suffix_encoder, GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_user_entity(&suffix_encoder, &dc.user, user_details);
      CHECK_CBOR_RET(ret);
    }
    if (has_multiple_credentials) {
      ret = cbor_encode_int(&suffix_encoder, GA_RESP_NUMBER_OF_CREDENTIALS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&suffix_encoder, number_of_credentials);
      CHECK_CBOR_RET(ret);
    }
    if (dc.has_large_blob_key) {
      uint8_t *large_blob_key = dc.cred_blob;
      ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&suffix_encoder, GA_RESP_LARGE_BLOB_KEY);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&suffix_encoder, large_blob_key, LARGE_BLOB_KEY_SIZE);
      CHECK_CBOR_RET(ret);
    }
    state->suffix_len = cbor_encoder_get_buffer_size(&suffix_encoder, state->suffix);
    state->kind = CTAP_MLDSA_STREAM_SIG;
    state->total_len = state->prefix_len + MLDSA_SIG_BYTES + state->suffix_len;
    state->pending = true;
    ++credential_counter;
    timer = device_get_tick();
    memzero(&key, sizeof(key));
    return 0;
  }
  memcpy(data_buf + len, ga.client_data_hash, CLIENT_DATA_HASH_SIZE);
  DBG_MSG("Message: ");
  PRINT_HEX(data_buf, len + CLIENT_DATA_HASH_SIZE);
  len = sign_with_private_key(dc.credential_id.alg_type, &key, data_buf, len + CLIENT_DATA_HASH_SIZE, data_buf);
  if (len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  DBG_MSG("Signature: ");
  PRINT_HEX(data_buf, len);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // user
  if (has_user) {
    ret = cbor_encode_int(&map, GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_user_entity(&map, &dc.user, user_details);
    CHECK_CBOR_RET(ret);
  }

  if (has_multiple_credentials) {
    ret = cbor_encode_int(&map, GA_RESP_NUMBER_OF_CREDENTIALS);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, number_of_credentials);
    CHECK_CBOR_RET(ret);
  }

  if (dc.has_large_blob_key) {
    uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
    static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
    ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, GA_RESP_LARGE_BLOB_KEY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  ++credential_counter;
  timer = device_get_tick();

  return 0;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetNextAssertion
static uint8_t ctap_get_next_assertion(CborEncoder *encoder) { return ctap_get_assertion(encoder, NULL, 0, true); }

// Pre-encoded CBOR segments for authenticatorGetInfo response.
// Generated at build time by scripts/gen_ctap_get_info.py.
// Constants are parsed from headers - see the .inc file for details.
#include "ctap_get_info_cbor.inc"

static uint8_t ctap_get_info(CborEncoder *encoder) {
  uint8_t *p = encoder->data.ptr;
  uint8_t *end = encoder->end;
  int sm2_algo = ctap_sm2_attr.algo_id;
  int sm2_in_alg_list = ctap_sm2_attr.enabled && (sm2_algo >= -256 && sm2_algo <= -25);
  size_t need = sizeof(cbor_gi_prefix) + 1 /* array header */
                + sizeof(cbor_gi_alg_base) + sizeof(cbor_gi_suffix) + (sm2_in_alg_list ? sizeof(cbor_gi_alg_sm2) : 0);
  if (p + need > end) return CTAP2_ERR_LIMIT_EXCEEDED;

  // 1. Prefix: map header through algorithms key
  memcpy(p, cbor_gi_prefix, sizeof(cbor_gi_prefix));
  p[CTAP_GI_CLIENT_PIN_OFFSET] = has_pin() ? 0xF5 : 0xF4;
  p += sizeof(cbor_gi_prefix);

  // 2. Algorithms array header: 3 or 4 entries
  *p++ = sm2_in_alg_list ? 0x84 : 0x83;

  // 3. Base algorithm entries (ES256 + EdDSA + ML-DSA-65)
  memcpy(p, cbor_gi_alg_base, sizeof(cbor_gi_alg_base));
  p += sizeof(cbor_gi_alg_base);

  // 4. SM2 entry (conditional)
  if (sm2_in_alg_list) {
    memcpy(p, cbor_gi_alg_sm2, sizeof(cbor_gi_alg_sm2));
    // Patch SM2 algo_id (CBOR negative int). The CBOR template encodes this
    // as a 2-byte negative integer (range [-256, -25]); we only include SM2
    // when the configured value matches this canonical encoding length.
    p[CTAP_GI_SM2_ALGO_OFFSET] = 0x38;
    p[CTAP_GI_SM2_ALGO_OFFSET + 1] = (uint8_t)(-1 - sm2_algo);
    p += sizeof(cbor_gi_alg_sm2);
  }

  // 5. Suffix: remaining fields
  memcpy(p, cbor_gi_suffix, sizeof(cbor_gi_suffix));
  p += sizeof(cbor_gi_suffix);

  encoder->data.ptr = p;
  return 0;
}

static uint8_t ctap_client_pin(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_client_pin cp;
  int ret = parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);

  CborEncoder map, key_map;
  uint8_t iv[16], buf[PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2], i;
  memzero(iv, sizeof(iv));
  uint8_t *ptr;
  int err, retries, cose_key_size;
  switch (cp.sub_command) {
  case CP_CMD_GET_PIN_RETRIES:
    DBG_MSG("Subcommand Get Pin Retries\n");
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CP_RESP_PIN_RETRIES);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, get_pin_retries());
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CP_CMD_GET_KEY_AGREEMENT:
    DBG_MSG("Subcommand Get Key Agreement\n");
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CP_RESP_KEY_AGREEMENT);
    CHECK_CBOR_RET(ret);
    // to save RAM, generate an empty key first, then fill it manually
    ret = cbor_encoder_create_map(&map, &key_map, 0);
    CHECK_CBOR_RET(ret);
    ptr = key_map.data.ptr - 1;
    cp_get_public_key(ptr);
    cose_key_size = build_cose_key(ptr, COSE_KEY_KTY_EC2, COSE_ALG_ECDH_ES_HKDF_256, COSE_KEY_CRV_P256, true);
    key_map.data.ptr = ptr + cose_key_size;
    ret = cbor_encoder_close_container(&map, &key_map);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CP_CMD_SET_PIN:
    DBG_MSG("Subcommand Set Pin\n");
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err > 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
    CHECK_PARSER_RET(ret);
    DBG_MSG("Shared Secret: ");
    PRINT_HEX(cp.key_agreement, cp.pin_uv_auth_protocol == 2 ? SHARED_SECRET_SIZE_P2 : SHARED_SECRET_SIZE_P1);
    if (!cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, cp.new_pin_enc,
                   cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2, cp.pin_uv_auth_param,
                   cp.pin_uv_auth_protocol)) {
      ERR_MSG("CP verification failed\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (cp_decrypt(cp.key_agreement, cp.new_pin_enc, cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2,
                   cp.new_pin_enc, cp.pin_uv_auth_protocol) != 0) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    DBG_MSG("Decrypted key: ");
    PRINT_HEX(cp.new_pin_enc, 64);
    i = 63;
    while (i > 0 && cp.new_pin_enc[i] == 0)
      --i;
    if (i < 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = set_pin(cp.new_pin_enc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CP_CMD_CHANGE_PIN:
    DBG_MSG("Subcommand Change Pin\n");
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    retries = err - 1;
#endif
    ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
    CHECK_PARSER_RET(ret);
    if (cp.pin_uv_auth_protocol == 1) {
      memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P1);
      memcpy(buf + PIN_ENC_SIZE_P1, cp.pin_hash_enc, PIN_HASH_SIZE_P1);
      ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, buf, PIN_ENC_SIZE_P1 + PIN_HASH_SIZE_P1,
                      cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
    } else {
      memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P2);
      memcpy(buf + PIN_ENC_SIZE_P2, cp.pin_hash_enc, PIN_HASH_SIZE_P2);
      ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, buf, PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2,
                      cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
    }
    if (ret == false) {
      ERR_MSG("CP verification failed\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cp_decrypt(cp.key_agreement, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol == 1 ? PIN_HASH_SIZE_P1 : PIN_HASH_SIZE_P2, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol)) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    err = verify_pin_hash(cp.pin_hash_enc);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err > 0) {
      cp_regenerate();
      if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
      --consecutive_pin_counter;
      if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      return CTAP2_ERR_PIN_INVALID;
    }
#endif
    consecutive_pin_counter = 3;
    if (cp_decrypt(cp.key_agreement, cp.new_pin_enc, cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2,
                   cp.new_pin_enc, cp.pin_uv_auth_protocol) != 0) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    i = 63;
    while (i > 0 && cp.new_pin_enc[i] == 0)
      --i;
    if (i < 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = set_pin(cp.new_pin_enc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CP_CMD_GET_PIN_TOKEN:
  case CP_CMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS:
    DBG_MSG("Subcommand Get Pin Token\n");
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    retries = err - 1;
#endif
    ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
    CHECK_PARSER_RET(ret);
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cp_decrypt(cp.key_agreement, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol == 1 ? PIN_HASH_SIZE_P1 : PIN_HASH_SIZE_P2, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol)) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    err = verify_pin_hash(cp.pin_hash_enc);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err > 0) {
      if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
      --consecutive_pin_counter;
      if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      return CTAP2_ERR_PIN_INVALID;
    }
#endif
    consecutive_pin_counter = 3;
    err = set_pin_retries(8);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cp_reset_pin_uv_auth_token();
    cp_begin_using_uv_auth_token(false);
    if (cp.sub_command == CP_CMD_GET_PIN_TOKEN) {
      cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA);
    } else {
      cp_set_permission(cp.permissions);
      if (cp.parsed_params & PARAM_RP) cp_associate_rp_id(cp.rp_id_hash);
    }
    cp_encrypt_pin_token(cp.key_agreement, buf, cp.pin_uv_auth_protocol);
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CP_RESP_PIN_UV_AUTH_TOKEN);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, buf, cp.pin_uv_auth_protocol == 1 ? PIN_TOKEN_SIZE : PIN_TOKEN_SIZE + 16);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;
  }

  return 0;
}

static int get_next_slot(uint64_t *slots, uint8_t *numbers) {
  int idx = -1;
  uint64_t val = *slots;
  *numbers = 0;
  for (int i = 0; i < 64; ++i) {
    if (val & 1) {
      ++*numbers;
      if (idx == -1) idx = i;
    }
    val >>= 1;
  }
  if (idx != -1) *slots &= ~(1ull << idx);
  return idx;
}

/**
 * Find a discoverable credential by credential_id.
 * On success, *dc is filled and *out_idx is set to the file index.
 *
 * @return 0 on success, CTAP2 error code on failure.
 */
static uint8_t cm_find_credential(const credential_id *target, CTAP_discoverable_credential *dc, int *out_idx) {
  int size = get_file_size(DC_FILE);
  if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  int n = size / (int)sizeof(CTAP_discoverable_credential);
  for (int i = 0; i < n; ++i) {
    size = read_file(DC_FILE, dc, i * (int)sizeof(CTAP_discoverable_credential), sizeof(CTAP_discoverable_credential));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (dc->deleted) continue;
    if (memcmp_s(&dc->credential_id, target, sizeof(credential_id)) == 0) {
      DBG_MSG("Found, credential_id: ");
      PRINT_HEX((const uint8_t *)target, sizeof(credential_id));
      *out_idx = i;
      return 0;
    }
  }
  return CTAP2_ERR_NO_CREDENTIALS;
}

static uint8_t ctap_credential_management(CborEncoder *encoder, const uint8_t *params, size_t len) {
  static uint8_t last_cm_cmd;

  CborParser parser;
  CTAP_credential_management cm;
  int ret = parse_credential_management(&parser, &cm, params, len);
  CHECK_PARSER_RET(ret);
  ret = ctap_consistency_check();
  CHECK_PARSER_RET(ret);

  static int idx, n_rp;  // for rp enumeration
  static uint64_t slots; // for credential enumeration
  int size, counter;
  CborEncoder map, sub_map;
  uint8_t numbers = 0;
  CTAP_rp_meta meta;
  CTAP_discoverable_credential dc;
  bool include_numbers;

  if (cm.sub_command == CM_CMD_GET_CREDS_METADATA || cm.sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
      cm.sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN || cm.sub_command == CM_CMD_DELETE_CREDENTIAL ||
      cm.sub_command == CM_CMD_UPDATE_USER_INFORMATION) {
    last_cm_cmd = cm.sub_command;
    uint8_t *buf = (uint8_t *)&dc; // buffer reuse
    _Static_assert(sizeof(CTAP_dc_general_attr) < sizeof(dc), "CTAP_dc_general_attr buffer overflow");
    if (read_attr(DC_FILE, DC_GENERAL_ATTR, buf, sizeof(CTAP_dc_general_attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    numbers = ((CTAP_dc_general_attr *)buf)->numbers;

    buf[0] = cm.sub_command;
    if (cm.param_len + 1 > sizeof(dc)) return CTAP1_ERR_INVALID_LENGTH;
    if (cm.param_len > 0) memcpy(&buf[1], cm.sub_command_params_ptr, cm.param_len);
    if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    if (!cp_verify_pin_token(buf, cm.param_len + 1, cm.pin_uv_auth_param, cm.pin_uv_auth_protocol)) {
      DBG_MSG("PIN verification error\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!cp_has_permission(CP_PERMISSION_CM)) return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  DBG_MSG("processing cm.sub_command %hhu\n", cm.sub_command);
  switch (cm.sub_command) {
  case CM_CMD_GET_CREDS_METADATA:
    if (cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
    ret = cbor_encoder_create_map(encoder, &map, 2);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_EXISTING_RESIDENT_CREDENTIALS_COUNT);
    CHECK_CBOR_RET(ret);
    DBG_MSG("Existing credentials: %d\n", numbers);
    ret = cbor_encode_int(&map, numbers);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_MAX_POSSIBLE_REMAINING_RESIDENT_CREDENTIALS_COUNT);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, MAX_DC_NUM - numbers);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CM_CMD_ENUMERATE_RPS_BEGIN:
    if (cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    size = get_file_size(DC_META_FILE), counter = 0;
    n_rp = size / (int)sizeof(CTAP_rp_meta);
    KEEPALIVE();
    for (int i = n_rp - 1; i >= 0; --i) {
      size = read_file(DC_META_FILE, &meta, i * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (meta.slots > 0) {
        idx = i;
        ++counter;
      }
    }
    DBG_MSG("%d RPs found\n", counter);
    size = read_file(DC_META_FILE, &meta, idx * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    goto encode_rp_begin;

  case CM_CMD_ENUMERATE_RPS_GET_NEXT_RP:
    if (last_cmd != CTAP_CREDENTIAL_MANAGEMENT ||
        (last_cm_cmd != CM_CMD_ENUMERATE_RPS_BEGIN && last_cm_cmd != CM_CMD_ENUMERATE_RPS_GET_NEXT_RP)) {
      last_cm_cmd = 0;
      return CTAP2_ERR_NOT_ALLOWED;
    }
    last_cm_cmd = cm.sub_command;
    {
      bool found = false;
      for (int i = idx + 1; i < n_rp; ++i) {
        size = read_file(DC_META_FILE, &meta, i * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots > 0) {
          DBG_MSG("Fetch RP at %d\n", i);
          idx = i;
          found = true;
          break;
        }
      }
      if (!found) return CTAP2_ERR_NOT_ALLOWED;
    }
    counter = -1; // signal: no TOTAL_RPS field
  encode_rp_begin:
    ret = cbor_encoder_create_map(encoder, &map, counter >= 0 ? 3 : 2);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_RP);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_create_map(&map, &sub_map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_string(&sub_map, (const char *)meta.rp_id, meta.rp_id_len);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_RP_ID_HASH);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, meta.rp_id_hash, SHA256_DIGEST_LENGTH);
    CHECK_CBOR_RET(ret);
    if (counter >= 0) {
      ret = cbor_encode_int(&map, CM_RESP_TOTAL_RPS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, counter);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CM_CMD_ENUMERATE_CREDENTIALS_BEGIN:
    if (!cp_verify_rp_id(cm.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    include_numbers = true;
    size = get_file_size(DC_META_FILE);
    n_rp = size / (int)sizeof(CTAP_rp_meta);
    KEEPALIVE();
    for (idx = 0; idx < n_rp; ++idx) {
      size = read_file(DC_META_FILE, &meta, idx * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (meta.slots == 0) continue;
      if (memcmp_s(meta.rp_id_hash, cm.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) break;
    }
    if (idx == n_rp) {
      DBG_MSG("Specified RP not found\n");
      return CTAP2_ERR_NO_CREDENTIALS;
    }
    DBG_MSG("Use meta at slot %d: ", idx);
    PRINT_HEX((const uint8_t *)&meta, sizeof(meta));
    slots = meta.slots;
  generate_credential_response:
    DBG_MSG("Current slot bitmap: 0x%llx\n", slots);
    idx = get_next_slot(&slots, &numbers);
    size =
        read_file(DC_FILE, &dc, idx * (int)sizeof(CTAP_discoverable_credential), sizeof(CTAP_discoverable_credential));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    DBG_MSG("Slot %d printed\n", idx);
    uint8_t *stream_resp_start = encoder->data.ptr;
    ret = cbor_encoder_create_map(encoder, &map, 4 + (uint8_t)include_numbers + (uint8_t)dc.has_large_blob_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_USER);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_user_entity(&map, &dc.user, true);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_CREDENTIAL_ID);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_credential_id(&map, &dc.credential_id);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_PUBLIC_KEY);
    CHECK_CBOR_RET(ret);
    if (dc.credential_id.alg_type == COSE_ALG_ML_DSA_65) {
      CTAP_mldsa_stream_state *state = &mldsa_stream_state;
      uint8_t *p;
      memset(state, 0, sizeof(*state));
      state->stage = global_buffer;
      if (verify_mldsa65_key_handle(&dc.credential_id, state->seed) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      p = state->prefix;
      *p++ = 0;
      memcpy(p, stream_resp_start, map.data.ptr - stream_resp_start);
      p += map.data.ptr - stream_resp_start;
      if (cbor_put_mldsa65_cose_prefix(&p) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      state->prefix_len = (size_t)(p - state->prefix);

      CborEncoder suffix_encoder;
      cbor_encoder_init(&suffix_encoder, state->suffix, sizeof(state->suffix), 0);
      if (include_numbers) {
        ret = cbor_encode_int(&suffix_encoder, CM_RESP_TOTAL_CREDENTIALS);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_int(&suffix_encoder, numbers);
        CHECK_CBOR_RET(ret);
      }
      ret = cbor_encode_int(&suffix_encoder, CM_RESP_CRED_PROTECT);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&suffix_encoder, dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS]);
      CHECK_CBOR_RET(ret);
      if (dc.has_large_blob_key) {
        uint8_t *large_blob_key = dc.cred_blob;
        ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_int(&suffix_encoder, CM_RESP_LARGE_BLOB_KEY);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_byte_string(&suffix_encoder, large_blob_key, LARGE_BLOB_KEY_SIZE);
        CHECK_CBOR_RET(ret);
      }
      state->suffix_len = cbor_encoder_get_buffer_size(&suffix_encoder, state->suffix);
      state->kind = CTAP_MLDSA_STREAM_PK;
      state->total_len = state->prefix_len + MLDSA_PK_BYTES + state->suffix_len;
      state->pending = true;
      break;
    }
    // to save RAM, generate an empty key first, then fill it manually
    ret = cbor_encoder_create_map(&map, &sub_map, 0);
    CHECK_CBOR_RET(ret);
    ecc_key_t key;
    ret = verify_key_handle(&dc.credential_id, &key);
    if (ret != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    key_type_t key_type = cose_alg_to_key_type(dc.credential_id.alg_type);
    if (ecc_complete_key(key_type, &key) < 0) {
      ERR_MSG("Failed to complete key\n");
      return -1;
    }
    uint8_t *ptr = sub_map.data.ptr - 1;
    memcpy(ptr, key.pub, PUBLIC_KEY_LENGTH[key_type]);
    if (dc.credential_id.alg_type == COSE_ALG_ES256) {
      int cose_key_size = build_cose_key(ptr, COSE_KEY_KTY_EC2, COSE_ALG_ES256, COSE_KEY_CRV_P256, true);
      sub_map.data.ptr = ptr + cose_key_size;
    } else if (dc.credential_id.alg_type == COSE_ALG_EDDSA) {
      int cose_key_size = build_cose_key(ptr, COSE_KEY_KTY_OKP, COSE_ALG_EDDSA, COSE_KEY_CRV_ED25519, false);
      sub_map.data.ptr = ptr + cose_key_size;
    }
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
    if (include_numbers) {
      ret = cbor_encode_int(&map, CM_RESP_TOTAL_CREDENTIALS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, numbers);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encode_int(&map, CM_RESP_CRED_PROTECT);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS]);
    CHECK_CBOR_RET(ret);
    if (dc.has_large_blob_key) {
      uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
      static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
      ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_LARGE_BLOB_KEY);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL:
    if (last_cmd != CTAP_CREDENTIAL_MANAGEMENT || (last_cm_cmd != CM_CMD_ENUMERATE_CREDENTIALS_BEGIN &&
                                                   last_cm_cmd != CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL)) {
      last_cm_cmd = 0;
      return CTAP2_ERR_NOT_ALLOWED;
    }
    last_cm_cmd = cm.sub_command;
    include_numbers = false;
    goto generate_credential_response;

  case CM_CMD_DELETE_CREDENTIAL:
    if (!cp_verify_rp_id(cm.credential_id.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    {
      uint8_t err = cm_find_credential(&cm.credential_id, &dc, &idx);
      if (err) return err;
    }

    CTAP_dc_general_attr attr;
    if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    attr.index = (uint8_t)idx;
    attr.pending_delete = 1;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

    // delete dc first
    dc.deleted = true;
    if (write_file(DC_FILE, &dc, idx * (int)sizeof(CTAP_discoverable_credential), sizeof(CTAP_discoverable_credential),
                   0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    DBG_MSG("Slot %d deleted\n", idx);
    // delete the meta then
    size = get_file_size(DC_META_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    numbers = size / sizeof(CTAP_rp_meta);
    KEEPALIVE();
    for (int i = 0; i < numbers; ++i) {
      size = read_file(DC_META_FILE, &meta, i * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (memcmp_s(meta.rp_id_hash, cm.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) {
        DBG_MSG("Orig slot bitmap: 0x%llx\n", meta.slots);
        meta.slots &= ~(1ull << idx);
        DBG_MSG("New slot bitmap: 0x%llx\n", meta.slots);
        size = write_file(DC_META_FILE, &meta, i * (int)sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta), 0);
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        break;
      }
    }
    attr.numbers--;
    attr.pending_delete = 0;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CM_CMD_UPDATE_USER_INFORMATION:
    if (!cp_verify_rp_id(cm.credential_id.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    KEEPALIVE();
    {
      uint8_t err = cm_find_credential(&cm.credential_id, &dc, &idx);
      if (err) return err;
    }
    if (dc.user.id_size != cm.user.id_size || memcmp_s(&dc.user.id, &cm.user.id, dc.user.id_size) != 0) {
      DBG_MSG("Incorrect user id\n");
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    memcpy(&dc.user, &cm.user, sizeof(user_entity));
    if (write_file(DC_FILE, &dc, idx * (int)sizeof(CTAP_discoverable_credential), sizeof(CTAP_discoverable_credential),
                   0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    DBG_MSG("Slot %d updated\n", idx);
    break;
  }

  return 0;
}

static uint8_t ctap_selection(void) {
  WAIT(CTAP2_ERR_USER_ACTION_TIMEOUT);
  return 0;
}

static uint8_t ctap_reset_data(void) {
  // If the request comes after 10 seconds of powering up, the authenticator returns CTAP2_ERR_NOT_ALLOWED.
  if (device_get_tick() > 10000) {
    return CTAP2_ERR_NOT_ALLOWED;
  }
  return ctap_install(1);
}

static uint8_t ctap_large_blobs(CborEncoder *encoder, const uint8_t *params, size_t len) {
  static uint16_t expectedNextOffset, expectedLength;

  CborParser parser;
  CborEncoder map;
  CTAP_large_blobs lb;
  uint8_t buf[256]; // for pin auth
  int ret = parse_large_blobs(&parser, &lb, params, len);
  CHECK_PARSER_RET(ret);

  // 1. If offset is not present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // 2. If neither get nor set are present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // 3. If both get and set are present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // > Step 1-3 are checked when parsing.

  // 4. If get is present in the input map:
  if (lb.parsed_params & PARAM_GET) {
    //  a) If length is present, return CTAP1_ERR_INVALID_PARAMETER.
    //  b) If either of pinUvAuthParam or pinUvAuthProtocol are present, return CTAP1_ERR_INVALID_PARAMETER.
    //  c) If the value of get is greater than maxFragmentLength, return CTAP1_ERR_INVALID_LENGTH.
    //  > Step a-c are checked when parsing.

    int size = get_file_size(LB_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    //  d) If the value of offset is greater than the length of the stored serialized large-blob array,
    //     return CTAP1_ERR_INVALID_PARAMETER.
    if ((int)lb.offset > size) {
      DBG_MSG("4-d not satisfied\n");
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    //  e) Return a CBOR map, as defined below, where the value of config is a substring of the stored serialized
    //     large-blob array. The substring SHOULD start at the offset given in offset and contain the number of bytes
    //     specified as get's value. If too few bytes exist at that offset, return the maximum number available.
    //     Note that if offset is equal to the length of the serialized large-blob array then this will result
    //     in a zero-length substring.
    if (lb.offset + (int)lb.get > size) lb.get = size - lb.offset;
    DBG_MSG("read %hu bytes at %hu\n", lb.get, lb.offset);
    KEEPALIVE();
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, LB_RESP_CONFIG);
    CHECK_CBOR_RET(ret);
    // to save RAM, we encode the buffer manually
    uint8_t *ptr = map.data.ptr;
    ret = cbor_encode_uint(&map, lb.get);
    CHECK_CBOR_RET(ret);
    *ptr |= 0x40; // CBOR Major type 2
    if (read_file(LB_FILE, map.data.ptr, lb.offset, lb.get) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    map.data.ptr += lb.get;
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
  } else {
    // 5. Else (implying that set is present in the input map):
    //    a) If the length of the value of set is greater than maxFragmentLength, return CTAP1_ERR_INVALID_LENGTH.
    //       > Checked when paring.
    //    b) If the value of offset is zero:
    if (lb.offset == 0) {
      //     i. If length is not present, return CTAP1_ERR_INVALID_PARAMETER.
      //     ii. If the value of length is greater than 1024 bytes and exceeds the capacity of the device,
      //         return CTAP2_ERR_LARGE_BLOB_STORAGE_FULL. (Authenticators MUST be capable of storing at least 1024
      //         bytes.)
      //     iii. If the value of length is less than 17, return CTAP1_ERR_INVALID_PARAMETER.
      //         > Step i - iii are checked when parsing.

      //     iv. Set expectedLength to the value of length.
      expectedLength = lb.length;
      //     v. Set expectedNextOffset to zero.
      expectedNextOffset = 0;
    }
    //    c) Else (i.e. the value of offset is not zero):
    //       If length is present, return CTAP1_ERR_INVALID_PARAMETER.
    //       > Checked when paring.
    //    d) If the value of offset is not equal to expectedNextOffset, return CTAP1_ERR_INVALID_SEQ.
    if (lb.offset != expectedNextOffset) {
      DBG_MSG("5-d not satisfied\n");
      return CTAP1_ERR_INVALID_SEQ;
    }
    //    e) If the authenticator is protected by some form of user verification
    //       or the alwaysUv option ID is present and true:
    if (has_pin()) {
      //     i. If pinUvAuthParam is absent from the input map, then end the operation by
      //        returning CTAP2_ERR_PUAT_REQUIRED.
      if (!(lb.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
        DBG_MSG("5-e-i not satisfied\n");
        return CTAP2_ERR_PUAT_REQUIRED;
      }
      //     ii. If pinUvAuthProtocol is absent from the input map, then end the operation by
      //         returning CTAP2_ERR_MISSING_PARAMETER.
      if (!(lb.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
        DBG_MSG("5-e-ii not satisfied\n");
        return CTAP2_ERR_MISSING_PARAMETER;
      }
      //     iii. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
      //       > Checked when paring.
      //     iv. The authenticator calls verify(pinUvAuthToken, 32×0xff || h'0c00' || uint32LittleEndian(offset) ||
      //         SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two),
      //         pinUvAuthParam).
      //         If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID.
      memset(buf, 0xFF, 32);
      buf[32] = 0x0C;
      buf[33] = 0x00;
      buf[34] = lb.offset & 0xFF;
      buf[35] = lb.offset >> 8;
      buf[36] = 0x00;
      buf[37] = 0x00;
      sha256_raw(lb.set, lb.set_len, buf + 38);
      if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      if (!cp_verify_pin_token(buf, 70, lb.pin_uv_auth_param, lb.pin_uv_auth_protocol)) {
        DBG_MSG("Fail to verify pin token\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //     v. Check if the pinUvAuthToken has the lbw permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
      if (!cp_has_permission(CP_PERMISSION_LBW)) {
        DBG_MSG("Fail to verify pin permission\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
    }
    //    f) If the sum of offset and the length of the value of set is greater than the value of expectedLength,
    //       return CTAP1_ERR_INVALID_PARAMETER.
    if (lb.offset + lb.set_len > (size_t)expectedLength) {
      DBG_MSG("5-g not satisfied, %hu + %zu > %hu\n", lb.offset, lb.set_len, expectedLength);
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    //    g) If the value of offset is zero, prepare a buffer to receive a new serialized large-blob array.
    //    h) Append the value of set to the buffer containing the pending serialized large-blob array.
    KEEPALIVE();
    if (write_file(LB_FILE_TMP, lb.set, lb.offset, lb.set_len, lb.offset == 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    //    i) Update expectedNextOffset to be the new length of the pending serialized large-blob array.
    expectedNextOffset += lb.set_len;
    //    j) If the length of the pending serialized large-blob array is equal to expectedLength:
    if (expectedNextOffset == expectedLength) {
      //     i. Verify that the final 16 bytes in the buffer are the truncated SHA-256 hash of the preceding bytes.
      //        If the hash does not match, return CTAP2_ERR_INTEGRITY_FAILURE.
      int offset = 0;
      expectedLength -= 16;
      sha256_ctx_t sha256;
      sha256_init(&sha256);
      while (offset < expectedLength) {
        int to_read = sizeof(buf);
        if (to_read > expectedLength - offset) to_read = expectedLength - offset;
        if (read_file(LB_FILE_TMP, buf, offset, to_read) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        sha256_update(&sha256, buf, to_read);
        offset += to_read;
      }
      sha256_final(&sha256, buf);
      if (read_file(LB_FILE_TMP, buf + 16, offset, 16) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (memcmp_s(buf, buf + 16, 16)) return CTAP2_ERR_INTEGRITY_FAILURE;
      //     ii. Commit the contents of the buffer as the new serialized large-blob array for this authenticator.
      if (fs_rename(LB_FILE_TMP, LB_FILE) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      //     iii. Return CTAP2_OK and an empty response.
    }
    //    k) Else:
    //       i. More data is needed to complete the pending serialized large-blob array.
    //       ii. Return CTAP2_OK and an empty response. Await further writes.
    //    > DO NOTHING
  }
  return 0;
}

static int ctap_process_cbor(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len) {
  if (req_len-- == 0) return -1;

  cp_pin_uv_auth_token_usage_timer_observer();

  CborEncoder encoder;
  cbor_encoder_init(&encoder, resp + 1, *resp_len - 1, 0);

  uint8_t cmd = *req++;
  uint8_t status = CTAP2_ERR_UNHANDLED_REQUEST;
  switch (cmd) {
  case CTAP_MAKE_CREDENTIAL:
    DBG_MSG("-----------------MC-------------------\n");
    status = ctap_make_credential(&encoder, req, req_len);
    goto set_resp;
  case CTAP_GET_ASSERTION:
    DBG_MSG("-----------------GA-------------------\n");
    status = ctap_get_assertion(&encoder, req, req_len, false);
    goto set_resp;
  case CTAP_GET_NEXT_ASSERTION:
    DBG_MSG("----------------NEXT------------------\n");
    status = ctap_get_next_assertion(&encoder);
    goto set_resp;
  case CTAP_GET_INFO:
    DBG_MSG("-----------------GI-------------------\n");
    status = ctap_get_info(&encoder);
    goto set_resp;
  case CTAP_CLIENT_PIN:
    DBG_MSG("-----------------CP-------------------\n");
    status = ctap_client_pin(&encoder, req, req_len);
    goto set_resp;
  case CTAP_RESET:
    DBG_MSG("----------------RESET-----------------\n");
    *resp = ctap_reset_data();
    goto finish_status_only;
  case CTAP_CRED_MANAGE_LEGACY: // compatible with old libfido2
    cmd = CTAP_CREDENTIAL_MANAGEMENT;
  case CTAP_CREDENTIAL_MANAGEMENT:
    DBG_MSG("----------------CM--------------------\n");
    status = ctap_credential_management(&encoder, req, req_len);
    goto set_resp;
  case CTAP_SELECTION:
    DBG_MSG("----------------SELECTION-------------\n");
    status = ctap_selection();
    goto set_resp;
  case CTAP_LARGE_BLOBS:
    DBG_MSG("----------------LB--------------------\n");
    status = ctap_large_blobs(&encoder, req, req_len);
    goto set_resp;
  case CTAP_CONFIG:
    DBG_MSG("----------------CONFIG----------------\n");
    *resp = CTAP2_ERR_UNHANDLED_REQUEST;
    goto finish_status_only;
  default:
    *resp = CTAP2_ERR_UNHANDLED_REQUEST;
    goto finish_status_only;
  }

set_resp:
  *resp = status;
  SET_RESP();
  goto finish;

finish_status_only:
  *resp_len = 1;

finish:
  last_cmd = cmd;
  if (*resp != 0) { // do not allow GET_NEXT_ASSERTION if error occurs
    last_cmd = CTAP_INVALID_CMD;
  }
  return 0;
}

int ctap_process_cbor_with_src(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len, ctap_src_t src) {

  if (current_cmd_src != CTAP_SRC_NONE) return -1;
  // Must set current_cmd_src to CTAP_SRC_NONE before return
  current_cmd_src = src;
  int ret = ctap_process_cbor(req, req_len, resp, resp_len);
  current_cmd_src = CTAP_SRC_NONE;
  return ret;
}

int ctap_process_cbor_stream_with_src(uint8_t *req, size_t req_len, uint8_t *scratch, size_t scratch_len,
                                      CTAPHID_TxSource *source, ctap_src_t src) {
  if (req_len == 0 || !scratch || scratch_len == 0 || !source) return -1;
  if (current_cmd_src != CTAP_SRC_NONE) return -1;

  memset(source, 0, sizeof(*source));
  memset(&mc_stream_state, 0, sizeof(mc_stream_state));
  memset(&mem_stream_state, 0, sizeof(mem_stream_state));
  memset(&mldsa_stream_state, 0, sizeof(mldsa_stream_state));
  if (acquire_apdu_buffer(BUFFER_OWNER_CTAPHID) != 0) return -1;
  uint8_t *resp = global_buffer;
  size_t resp_len = APDU_BUFFER_SIZE;

  if (*req != CTAP_MAKE_CREDENTIAL) {
    current_cmd_src = src;
    int ret = ctap_process_cbor(req, req_len, resp, &resp_len);
    current_cmd_src = CTAP_SRC_NONE;
    if (ret < 0) {
      release_apdu_buffer(BUFFER_OWNER_CTAPHID);
      return -1;
    }
    if (mldsa_stream_state.pending && resp[0] == 0) {
      source->total_len = mldsa_stream_state.total_len;
      source->read = ctap_mldsa_stream_read;
      source->close = ctap_hid_stream_close;
      source->ctx = &mldsa_stream_state;
      return 1;
    }

    mem_stream_state.buf = resp;
    mem_stream_state.len = resp_len;
    mem_stream_state.emitted = 0;
    source->total_len = mem_stream_state.len;
    source->read = ctap_mem_stream_read;
    source->close = ctap_hid_stream_close;
    source->ctx = &mem_stream_state;
    return 1;
  }

  stream_resp_base = resp;
  stream_make_credential_response = true;

  CborEncoder encoder;
  cbor_encoder_init(&encoder, resp + 1, resp_len - 1, 0);

  current_cmd_src = src;
  uint8_t status = ctap_make_credential(&encoder, req + 1, req_len - 1);
  current_cmd_src = CTAP_SRC_NONE;
  stream_make_credential_response = false;
  stream_resp_base = NULL;

  resp[0] = status;
  last_cmd = CTAP_MAKE_CREDENTIAL;
  if (status != 0) last_cmd = CTAP_INVALID_CMD;

  if (status == 0 && mc_stream_state.prepared) {
    source->total_len = mc_stream_state.total_len;
    source->read = ctap_make_credential_stream_read;
    source->close = ctap_hid_stream_close;
    source->ctx = &mc_stream_state;
    return 1;
  }

  mem_stream_state.buf = resp;
  mem_stream_state.len = status == 0 ? 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1) : 1;
  mem_stream_state.emitted = 0;
  source->total_len = mem_stream_state.len;
  source->read = ctap_mem_stream_read;
  source->close = ctap_hid_stream_close;
  source->ctx = &mem_stream_state;
  return 1;
}

int ctap_process_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src) {
  int ret = 0;
  LL = 0;
  if (current_cmd_src != CTAP_SRC_NONE) EXCEPT(SW_UNABLE_TO_PROCESS);
  // Must set current_cmd_src to CTAP_SRC_NONE before return
  current_cmd_src = src;
  SW = SW_NO_ERROR;
  if (CLA == 0x80) {
    if (INS == CTAP_INS_MSG) {
      // rapdu buffer size: APDU_BUFFER_SIZE
      size_t len = APDU_BUFFER_SIZE;

      ret = ctap_process_cbor(DATA, LC, RDATA, &len);
      // len is the actual len written to RDATA
      LL = len;
    } else {
      current_cmd_src = CTAP_SRC_NONE;
      EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else if (CLA == 0x00) {
    switch (INS) {
    case U2F_REGISTER:
      ret = u2f_register(capdu, rapdu);
      break;
    case U2F_AUTHENTICATE:
      ret = u2f_authenticate(capdu, rapdu);
      break;
    case U2F_VERSION:
      ret = u2f_version(capdu, rapdu);
      break;
    case U2F_SELECT:
      ret = u2f_select(capdu, rapdu);
      break;
    case CTAP_INS_MSG:
      break;
    default:
      current_cmd_src = CTAP_SRC_NONE;
      EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else {
    current_cmd_src = CTAP_SRC_NONE;
    EXCEPT(SW_CLA_NOT_SUPPORTED);
  }

  current_cmd_src = CTAP_SRC_NONE;
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  else
    return 0;
}

int ctap_wink(void) {
  start_blinking_interval(1, 50);
  return 0;
}
