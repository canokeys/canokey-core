// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <apdu.h>
#include <applets.h>
#include <common.h>
#include <ctap.h>
#include <device-config.h>
#include <device.h>
#include <pke.h>
#if ENABLE_APPLET_NDEF
#include <ndef.h>
#endif
#include <oath.h>
#include <openpgp.h>
#include <piv.h>
#if ENABLE_IFACE_KBDHID
#include <kbdhid.h>
#endif

enum APPLET {
  APPLET_NULL,
  APPLET_PIV,
  APPLET_FIDO,
  APPLET_OATH,
  APPLET_ADMIN,
  APPLET_OPENPGP,
#if ENABLE_APPLET_NDEF
  APPLET_NDEF,
#endif
  APPLET_ENUM_END,
} current_applet;

static const uint8_t PIV_AID[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t OATH_AID[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01};
static const uint8_t ADMIN_AID[] = {0xF0, 0x00, 0x00, 0x00, 0x00};
static const uint8_t OPENPGP_AID[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static const uint8_t FIDO_AID[] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
#if ENABLE_APPLET_NDEF
static const uint8_t NDEF_AID[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
#endif

static const uint8_t *const AID[] = {
    [APPLET_NULL] = NULL,     [APPLET_PIV] = PIV_AID,     [APPLET_FIDO] = FIDO_AID,
    [APPLET_OATH] = OATH_AID, [APPLET_ADMIN] = ADMIN_AID, [APPLET_OPENPGP] = OPENPGP_AID,
#if ENABLE_APPLET_NDEF
    [APPLET_NDEF] = NDEF_AID,
#endif
};

static const uint8_t AID_Size[] = {
    [APPLET_NULL] = 0,
    [APPLET_PIV] = sizeof(PIV_AID),
    [APPLET_FIDO] = sizeof(FIDO_AID),
    [APPLET_OATH] = sizeof(OATH_AID),
    [APPLET_ADMIN] = sizeof(ADMIN_AID),
    [APPLET_OPENPGP] = sizeof(OPENPGP_AID),
#if ENABLE_APPLET_NDEF
    [APPLET_NDEF] = sizeof(NDEF_AID),
#endif
};

static volatile uint32_t buffer_owner;
static RAPDU_CHAINING rapdu_chaining;
static CAPDU_CHAINING fido_capdu_chaining;
static uint8_t fido_capdu_uses_pke;
static uint8_t fido_capdu_pke_owner;
static uint8_t response_tail[APDU_COMMAND_OVERHEAD];
static uint16_t response_tail_offset;
static uint16_t response_tail_len;
uint8_t *shared_io_buffer;
#if !ENABLE_IFACE_CCID
static uint8_t apdu_fallback_buffer[APDU_COMMAND_BUFFER_SIZE];
#endif

static void fido_capdu_reset(void);

typedef struct {
  uint8_t active;
  uint32_t total_len;
  uint32_t sent;
  uint16_t sw;
  APDU_RESPONSE_SOURCE_READ read;
  APDU_RESPONSE_SOURCE_CLOSE close;
  void *ctx;
} APDU_RESPONSE_SOURCE;

static uint8_t is_fido_apdu(const CAPDU *capdu) {
  // Allow implicit routing for both standalone and chained CTAP2 CBOR APDUs.
  if ((capdu->cla & 0xEF) == 0x80 && capdu->ins == 0x10) return 1;
  // NFC CTAP GET_RESPONSE may arrive after a reader reconnect clears the
  // selected applet; keep routing the poll back to FIDO so pending work can
  // finish instead of falling through to SW_FILE_NOT_FOUND.
  if (is_nfc() && capdu->cla == 0x80 && capdu->ins == 0x11) return 1;
#ifdef TEST
  if (capdu->cla == 0x00 && (capdu->ins == 0xEE || capdu->ins == 0xEF)) return 1;
#endif
  if (capdu->cla != 0x00) return 0;

  switch (capdu->ins) {
  case 0x01: // U2F_REGISTER
  case 0x02: // U2F_AUTHENTICATE
  case 0x03: // U2F_VERSION
    return 1;
  case 0xA4: // U2F_SELECT, distinct from ISO SELECT by P1/P2
    return !(capdu->p1 == 0x04 && capdu->p2 == 0x00);
  default:
    return 0;
  }
}

static uint8_t applet_enabled_on_transport(enum APPLET applet, apdu_transport_t transport) {
  switch (applet) {
  case APPLET_OPENPGP:
    return transport == APDU_TRANSPORT_NFC ? device_config_is_openpgp_nfc_enabled() : device_config_is_openpgp_ccid_enabled();
  case APPLET_PIV:
    return transport == APDU_TRANSPORT_NFC ? device_config_is_piv_nfc_enabled() : device_config_is_piv_ccid_enabled();
  case APPLET_FIDO:
    return device_config_is_webauthn_enabled();
  default:
    return 1;
  }
}

static void rapdu_chaining_reset(void) {
  memset(&rapdu_chaining, 0, sizeof(rapdu_chaining));
  rapdu_chaining.rapdu.data = shared_io_buffer;
}

static void disabled_applet_response(RAPDU *rapdu) {
  current_applet = APPLET_NULL;
  apdu_response_source_clear();
  rapdu_chaining_reset();
  fido_capdu_reset();
  LL = 0;
  SW = SW_FILE_NOT_FOUND;
}

static APDU_RESPONSE_SOURCE response_source;

#define APDU_RESPONSE_CHUNK_SIZE 250

#if ENABLE_IFACE_CCID
extern void ccid_init_apdu_buffer(void);
#endif

void init_apdu_buffer(void) {
#if !ENABLE_IFACE_CCID
  shared_io_buffer = apdu_fallback_buffer;
#endif
  apdu_response_source_clear();
  if (!fido_capdu_chaining.in_chaining) {
    memset(&fido_capdu_chaining, 0, sizeof(fido_capdu_chaining));
    fido_capdu_uses_pke = 0;
    fido_capdu_pke_owner = 0;
  }
  current_applet = APPLET_NULL;
#if ENABLE_IFACE_CCID
  ccid_init_apdu_buffer();
#endif
  rapdu_chaining_reset();
  if (!fido_capdu_uses_pke) fido_capdu_chaining.capdu.data = shared_io_buffer;
}

int build_capdu(CAPDU *capdu, const uint8_t *cmd, uint16_t len) {
  if (len < 4) return -1;
  CLA = cmd[0];
  INS = cmd[1];
  P1 = cmd[2];
  P2 = cmd[3];
  LC = 0;
  LE = 0;
  capdu->extended = 0;

  if (len == 4) // Case 1
    return 0;
  LC = cmd[4];
  if (len == 5) { // Case 2S
    LE = LC;
    LC = 0;
    if (LE == 0) LE = 0x100;
  } else if (LC > 0 && len == 5 + LC) { // Case 3S
    if (LC > APDU_INCOMING_DATA_SIZE) return -1;
    memmove(DATA, cmd + 5, LC);
    LE = 0x100;
  } else if (LC > 0 && len == 6 + LC) { // Case 4S
    if (LC > APDU_INCOMING_DATA_SIZE) return -1;
    memmove(DATA, cmd + 5, LC);
    LE = cmd[5 + LC];
    if (LE == 0) LE = 0x100;
  } else if (len == 7) { // Case 2E
    if (LC != 0) return -1;
    capdu->extended = 1;
    LE = (cmd[5] << 8) | cmd[6];
    if (LE == 0) LE = 0x10000;
  } else {
    if (LC != 0 || len < 7) return -1;
    capdu->extended = 1;
    LC = (cmd[5] << 8) | cmd[6];
    if (LC == 0) return -1;
    if (len == 7 + LC) { // Case 3E
      if (LC > APDU_INCOMING_DATA_SIZE) return -1;
      memmove(DATA, cmd + 7, LC);
      LE = 0x10000;
      return 0;
    } else if (len == 9 + LC) { // Case 4E
      if (LC > APDU_INCOMING_DATA_SIZE) return -1;
      memmove(DATA, cmd + 7, LC);
      LE = (cmd[7 + LC] << 8) | cmd[8 + LC];
      if (LE == 0) LE = 0x10000;
    } else
      return -1;
  }
  return 0;
}

int apdu_input(CAPDU_CHAINING *ex, const CAPDU *sh) {
restart:
  if (!ex->in_chaining) {
    ex->capdu.cla = sh->cla & 0xEF;
    ex->capdu.ins = sh->ins;
    ex->capdu.p1 = sh->p1;
    ex->capdu.p2 = sh->p2;
    ex->capdu.lc = 0;
    ex->capdu.extended = sh->extended;
  } else if (ex->capdu.cla != (sh->cla & 0xEF) || ex->capdu.ins != sh->ins || ex->capdu.p1 != sh->p1 ||
             ex->capdu.p2 != sh->p2) {
    ex->in_chaining = 0;
    goto restart;
  }
  ex->in_chaining = 1;
  if (ex->capdu.lc + sh->lc > APDU_INCOMING_DATA_SIZE) return APDU_CHAINING_OVERFLOW;
  memcpy(ex->capdu.data + ex->capdu.lc, sh->data, sh->lc);
  ex->capdu.lc += sh->lc;

  if (sh->cla & 0x10) // not last block
    return APDU_CHAINING_NOT_LAST_BLOCK;
  else {
    ex->in_chaining = 0;
    ex->capdu.le = sh->le;
    return APDU_CHAINING_LAST_BLOCK;
  }
}

static void fido_capdu_reset(void) {
  if (fido_capdu_uses_pke && fido_capdu_pke_owner) {
    pke_buffer_clear();
    pke_buffer_release(PKE_BUFFER_OWNER_CTAP);
  }
  memset(&fido_capdu_chaining, 0, sizeof(fido_capdu_chaining));
  fido_capdu_chaining.capdu.data = shared_io_buffer;
  fido_capdu_uses_pke = 0;
  fido_capdu_pke_owner = 0;
}

void apdu_fido_chain_reset(void) { fido_capdu_reset(); }

static int fido_apdu_input(const CAPDU *sh) {
restart:
  if (!fido_capdu_chaining.in_chaining) {
    fido_capdu_chaining.capdu.cla = sh->cla & 0xEF;
    fido_capdu_chaining.capdu.ins = sh->ins;
    fido_capdu_chaining.capdu.p1 = sh->p1;
    fido_capdu_chaining.capdu.p2 = sh->p2;
    fido_capdu_chaining.capdu.lc = 0;
    fido_capdu_chaining.capdu.extended = sh->extended;
    fido_capdu_chaining.capdu.data = shared_io_buffer;
  } else if (fido_capdu_chaining.capdu.cla != (sh->cla & 0xEF) || fido_capdu_chaining.capdu.ins != sh->ins ||
             fido_capdu_chaining.capdu.p1 != sh->p1 || fido_capdu_chaining.capdu.p2 != sh->p2) {
    fido_capdu_reset();
    goto restart;
  }

  const uint32_t new_len = (uint32_t)fido_capdu_chaining.capdu.lc + sh->lc;
  if (new_len > CTAP_MAX_REQUEST_SIZE || new_len > pke_buffer_size()) return APDU_CHAINING_OVERFLOW;

  // Once a chained FIDO request spans multiple APDUs, the next build_capdu()
  // call will reuse shared_io_buffer for the incoming fragment. Move the
  // accumulated payload out of shared_io_buffer before that can overwrite the
  // earlier bytes.
  if (!fido_capdu_uses_pke &&
      ((sh->cla & 0x10) != 0 || fido_capdu_chaining.in_chaining || new_len > APDU_INCOMING_DATA_SIZE)) {
    if (pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP) < 0) return APDU_CHAINING_ERROR;
    fido_capdu_pke_owner = 1;
    if (fido_capdu_chaining.capdu.lc != 0 &&
        pke_buffer_write(0, fido_capdu_chaining.capdu.data, fido_capdu_chaining.capdu.lc) < 0) {
      pke_buffer_release(PKE_BUFFER_OWNER_CTAP);
      fido_capdu_pke_owner = 0;
      return APDU_CHAINING_ERROR;
    }
    fido_capdu_uses_pke = 1;
  }

  fido_capdu_chaining.in_chaining = 1;
  if (fido_capdu_uses_pke) {
    if (pke_buffer_write(fido_capdu_chaining.capdu.lc, sh->data, sh->lc) < 0) return APDU_CHAINING_ERROR;
  } else {
    memcpy(fido_capdu_chaining.capdu.data + fido_capdu_chaining.capdu.lc, sh->data, sh->lc);
  }
  fido_capdu_chaining.capdu.lc = (uint16_t)new_len;

  if (sh->cla & 0x10) return APDU_CHAINING_NOT_LAST_BLOCK;

  fido_capdu_chaining.in_chaining = 0;
  fido_capdu_chaining.capdu.le = sh->le;
  return APDU_CHAINING_LAST_BLOCK;
}

int apdu_output(RAPDU_CHAINING *ex, RAPDU *sh) {
  if (ex->sent == 0 && !response_source.active) {
    response_tail_offset = 0;
    response_tail_len = 0;
  }

  if (response_source.active) {
    uint32_t remaining = response_source.total_len - response_source.sent;
    uint16_t to_send = (uint16_t)MIN(remaining, sh->len);

    // The caller writes SW to sh->data + sh->len after we return, which
    // overwrites bytes that the response source may still need (e.g. the
    // tail of the auth_data in the first chunk of an MC streaming response).
    // Restore any bytes saved on the previous call.
    if (response_tail_len != 0 && response_source.sent == response_tail_offset) {
      memcpy(sh->data + response_tail_offset, response_tail, response_tail_len);
      response_tail_len = 0;
    }

    int read = response_source.read(response_source.ctx, response_source.sent, sh->data, to_send);
    if (read < 0 || read > to_send || (read == 0 && remaining != 0)) {
      ERR_MSG("source read failed sent=%lu read=%d\n", (unsigned long)response_source.sent, read);
      apdu_response_source_clear();
      sh->len = 0;
      sh->sw = SW_UNABLE_TO_PROCESS;
      return -1;
    }

    // Save the two bytes at the end of this chunk so that the SW byte
    // write by the caller does not corrupt response source data.
    if (sh->data == shared_io_buffer && remaining > (uint32_t)read) {
      const uint16_t tail_len = 2;
      memcpy(response_tail, sh->data + read, tail_len);
      response_tail_offset = (uint16_t)read;
      response_tail_len = tail_len;
    }

    sh->len = (uint16_t)read;
    response_source.sent += (uint16_t)read;
    remaining = response_source.total_len - response_source.sent;
    if (remaining != 0) {
      sh->sw = remaining > 0xFF ? 0x61FF : 0x6100 + remaining;
    } else {
      sh->sw = response_source.sw;
      apdu_response_source_clear();
    }
    return 0;
  }

  uint16_t to_send = ex->rapdu.len - ex->sent;
  if (to_send > sh->len) to_send = sh->len;
  if (ex->sent == 0 && ex->rapdu.data == sh->data && ex->rapdu.len > to_send) {
    const uint16_t tail_len = ex->rapdu.len - to_send;
    if (tail_len <= sizeof(response_tail)) {
      memcpy(response_tail, ex->rapdu.data + to_send, tail_len);
      response_tail_offset = to_send;
      response_tail_len = tail_len;
    }
  }
  if (response_tail_len != 0 && ex->sent >= response_tail_offset) {
    memcpy(sh->data, response_tail + ex->sent - response_tail_offset, to_send);
  } else {
    memcpy(sh->data, ex->rapdu.data + ex->sent, to_send);
  }
  sh->len = to_send;
  ex->sent += to_send;
  if (ex->sent < ex->rapdu.len) {
    if (ex->rapdu.len - ex->sent > 0xFF)
      sh->sw = 0x61FF;
    else
      sh->sw = 0x6100 + (ex->rapdu.len - ex->sent);
  } else {
    sh->sw = ex->rapdu.sw;
    response_tail_offset = 0;
    response_tail_len = 0;
  }
  return 0;
}

uint8_t apdu_is_get_response(const CAPDU *capdu) {
  return (capdu->cla == 0x00 || capdu->cla == 0x80) && capdu->ins == 0xC0;
}

int apdu_process_streaming_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu, uint8_t is_get_response,
                                   uint16_t le_limit, APDU_MESSAGE_HANDLER handler) {
  const uint16_t response_le = (uint16_t)MIN(capdu->le, le_limit);
  if (!handler) return -1;

  if (!is_get_response) apdu_response_source_clear();
  if (is_get_response) {
    rapdu->len = response_le;
    apdu_output(rapdu_chaining, rapdu);
    return 0;
  }

  rapdu_chaining->sent = 0;
  handler(capdu, &rapdu_chaining->rapdu);
  rapdu->len = response_le;
  apdu_output(rapdu_chaining, rapdu);
  return 0;
}

void apdu_response_source_set(uint32_t total_len, uint16_t sw, APDU_RESPONSE_SOURCE_READ read,
                              APDU_RESPONSE_SOURCE_CLOSE close, void *ctx) {
  apdu_response_source_clear();
  response_source.active = 1;
  response_source.total_len = total_len;
  response_source.sent = 0;
  response_source.sw = sw;
  response_source.read = read;
  response_source.close = close;
  response_source.ctx = ctx;
}

void apdu_response_source_clear(void) {
  if (response_source.active && response_source.close) response_source.close(response_source.ctx);
  memset(&response_source, 0, sizeof(response_source));
}

int apdu_response_source_active(void) { return response_source.active != 0; }

int apdu_session_can_preempt(void) {
  if (buffer_owner != BUFFER_OWNER_NONE) return 0;
  if (response_source.active) return 0;
  if (rapdu_chaining.sent < rapdu_chaining.rapdu.len) return 0;
  if (fido_capdu_chaining.in_chaining || fido_capdu_uses_pke) return 0;
  return 1;
}

int acquire_apdu_interface(uint8_t session_owner, uint8_t buffer_owner) {
  if (device_applet_session_acquire((device_applet_session_owner_t)session_owner) != 0) return -1;
  if (acquire_apdu_buffer(buffer_owner) != 0) {
    device_applet_session_release((device_applet_session_owner_t)session_owner);
    return -1;
  }
  device_applet_session_touch((device_applet_session_owner_t)session_owner);
  return 0;
}

void release_apdu_interface(uint8_t session_owner, uint8_t buffer_owner) {
  release_apdu_buffer(buffer_owner);
  device_applet_session_release((device_applet_session_owner_t)session_owner);
}

void process_apdu_from(CAPDU *capdu, RAPDU *rapdu, apdu_transport_t transport) {
#if ENABLE_IFACE_KBDHID
  if (device_config_is_pass_enabled() && CLA == 0xFF && INS == 0xEE && P1 == 0xFF && P2 == 0xEE) {
    // A special APDU to trigger Eject
    KBDHID_Eject();
    LL = 0;
    SW = SW_NO_ERROR;
    return;
  }
#endif
  if (!(CLA == 0x00 && INS == 0xA4 && P1 == 0x04 && P2 == 0x00)) {
    if (current_applet == APPLET_PIV) {
      if (!applet_enabled_on_transport(APPLET_PIV, transport)) {
        disabled_applet_response(rapdu);
        return;
      }
      piv_process_apdu_message(&rapdu_chaining, capdu, rapdu);
      return;
    }
    if (current_applet == APPLET_OPENPGP) {
      if (!applet_enabled_on_transport(APPLET_OPENPGP, transport)) {
        disabled_applet_response(rapdu);
        return;
      }
      openpgp_process_apdu_message(&rapdu_chaining, capdu, rapdu);
      return;
    }
#if ENABLE_APPLET_NDEF
    if (current_applet == APPLET_NDEF) {
      ndef_process_apdu_message(&rapdu_chaining, capdu, rapdu);
      return;
    }
#endif
  }
  const uint8_t is_get_response = (CLA == 0x00 || CLA == 0x80) && INS == 0xC0;
  if (!is_get_response) apdu_response_source_clear();
  LE = MIN(LE, APDU_BUFFER_SIZE);
  if (is_get_response) { // GET RESPONSE
    if (!apdu_response_source_active() && rapdu_chaining.sent >= rapdu_chaining.rapdu.len) {
      LL = 0;
      SW = SW_COMMAND_NOT_ALLOWED;
      return;
    }
    rapdu->len = MIN(LE, apdu_response_source_active() ? APDU_RESPONSE_CHUNK_SIZE : APDU_BUFFER_SIZE);
    apdu_output(&rapdu_chaining, rapdu);
    return;
  }
  rapdu_chaining.sent = 0;
  if (CLA == 0x00 && INS == 0xA4 && P1 == 0x04 && P2 == 0x00) {
    uint8_t i, end = APPLET_ENUM_END;
    for (i = APPLET_NULL + 1; i != end; ++i) {
      if (LC >= AID_Size[i] && memcmp(DATA, AID[i], AID_Size[i]) == 0) {
        if (!applet_enabled_on_transport((enum APPLET)i, transport)) {
          disabled_applet_response(rapdu);
          DBG_MSG("applet disabled: %d\n", i);
          return;
        }
#if ENABLE_APPLET_NDEF
        if (i == APPLET_NDEF && !device_config_is_ndef_enabled()) {
          LL = 0;
          SW = SW_FILE_NOT_FOUND;
          DBG_MSG("NDEF is disable\n");
          return;
        }
#endif
        if (i != current_applet) {
          if (current_applet == APPLET_FIDO) {
            ctap_deselect();
          }
          applets_poweroff();
          fido_capdu_reset();
        }
        current_applet = i;
        DBG_MSG("applet switched to: %d\n", current_applet);
        break;
      }
    }
    if (i == end) {
      LL = 0;
      SW = SW_FILE_NOT_FOUND;
      DBG_MSG("applet not found\n");
      return;
    }
  }
  if (current_applet == APPLET_NULL && is_fido_apdu(capdu)) {
    // Some PC/SC stacks reconnect or reset the card between CTAP INIT and the
    // next CBOR/U2F exchange. Accepting unmistakably FIDO APDUs here keeps the
    // FIDO CCID path usable across those implicit resets.
    if (!applet_enabled_on_transport(APPLET_FIDO, transport)) {
      disabled_applet_response(rapdu);
      return;
    }
    current_applet = APPLET_FIDO;
    DBG_MSG("implicit applet switched to: %d\n", current_applet);
  }
  switch (current_applet) {
  case APPLET_OPENPGP:
    openpgp_process_apdu(capdu, &rapdu_chaining.rapdu);
    rapdu->len = MIN(LE, apdu_response_source_active() ? APDU_RESPONSE_CHUNK_SIZE : APDU_BUFFER_SIZE);
    apdu_output(&rapdu_chaining, rapdu);
    break;
  case APPLET_PIV:
    piv_process_apdu(capdu, &rapdu_chaining.rapdu);
    rapdu->len = MIN(LE, apdu_response_source_active() ? APDU_RESPONSE_CHUNK_SIZE : APDU_BUFFER_SIZE);
    apdu_output(&rapdu_chaining, rapdu);
    break;
  case APPLET_FIDO:
    if (!applet_enabled_on_transport(APPLET_FIDO, transport)) {
      disabled_applet_response(rapdu);
      break;
    }
#ifdef TEST
    if (CLA == 0x00 && INS == 0xEE && LC == 0x04 && memcmp(DATA, "\x12\x56\xAB\xF0", 4) == 0) {
      printf("MAGIC REBOOT command received!\r\n");
      testmode_set_initial_ticks(0);
      testmode_set_initial_ticks(device_get_tick());
      ctap_schedule_runtime_reset();
      ctap_install(0);
      SW = 0x9000;
      LL = 0;
      break;
    }
    if (CLA == 0x00 && INS == 0xEF) {
      testmode_inject_error(P1, P2, LC, DATA);
      SW = 0x9000;
      LL = 0;
      break;
    }
#endif
    if (((CLA & 0xEF) == 0x80) && ((CLA & 0x10) != 0 || fido_capdu_chaining.in_chaining)) {
      const int chaining = fido_apdu_input(capdu);
      if (chaining == APDU_CHAINING_OVERFLOW) {
        fido_capdu_reset();
        LL = 0;
        SW = SW_WRONG_LENGTH;
        break;
      }
      if (chaining == APDU_CHAINING_ERROR) {
        fido_capdu_reset();
        LL = 0;
        SW = SW_UNABLE_TO_PROCESS;
        break;
      }
      if (chaining == APDU_CHAINING_NOT_LAST_BLOCK) {
        LL = 0;
        SW = SW_NO_ERROR;
        break;
      }
      capdu = &fido_capdu_chaining.capdu;
    }
    if (fido_capdu_uses_pke)
      ctap_process_pke_apdu_with_src(capdu, &rapdu_chaining.rapdu, CTAP_SRC_CCID);
    else
      ctap_process_apdu_with_src(capdu, &rapdu_chaining.rapdu, CTAP_SRC_CCID);
    rapdu->len = MIN(LE, apdu_response_source_active() ? APDU_RESPONSE_CHUNK_SIZE : APDU_BUFFER_SIZE);
    apdu_output(&rapdu_chaining, rapdu);
    fido_capdu_reset();
    break;
  case APPLET_OATH:
    oath_process_apdu(capdu, rapdu);
    break;
  case APPLET_ADMIN:
    admin_process_apdu(capdu, rapdu);
    break;
#if ENABLE_APPLET_NDEF
  case APPLET_NDEF:
    ndef_process_apdu(capdu, rapdu);
    break;
#endif
  default:
    LL = 0;
    SW = SW_FILE_NOT_FOUND;
  }
}

void process_apdu(CAPDU *capdu, RAPDU *rapdu) { process_apdu_from(capdu, rapdu, APDU_TRANSPORT_CCID); }

int acquire_apdu_buffer(uint8_t owner) {
  device_atomic_compare_and_swap(&buffer_owner, BUFFER_OWNER_NONE, owner);
  return buffer_owner == owner ? 0 : -1;
}

int release_apdu_buffer(uint8_t owner) {
  device_atomic_compare_and_swap(&buffer_owner, owner, BUFFER_OWNER_NONE);
  return buffer_owner == BUFFER_OWNER_NONE ? 0 : -1;
}
