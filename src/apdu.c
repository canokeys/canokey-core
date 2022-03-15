// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <apdu.h>
#include <applets.h>
#include <common.h>
#include <ctap.h>
#include <device.h>
#include <meta.h>
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <piv.h>

enum APPLET {
  APPLET_NULL,
  APPLET_PIV,
  APPLET_FIDO,
  APPLET_OATH,
  APPLET_ADMIN,
  APPLET_OPENPGP,
  APPLET_NDEF,
  APPLET_META,
  APPLET_ENUM_END,
} current_applet;

static const uint8_t PIV_AID[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t OATH_AID[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01};
static const uint8_t ADMIN_AID[] = {0xF0, 0x00, 0x00, 0x00, 0x00};
static const uint8_t OPENPGP_AID[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static const uint8_t FIDO_AID[] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
static const uint8_t NDEF_AID[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
static const uint8_t META_AID[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};

static const uint8_t *const AID[] = {
    [APPLET_NULL] = NULL,       [APPLET_PIV] = PIV_AID,         [APPLET_FIDO] = FIDO_AID, [APPLET_OATH] = OATH_AID,
    [APPLET_ADMIN] = ADMIN_AID, [APPLET_OPENPGP] = OPENPGP_AID, [APPLET_NDEF] = NDEF_AID, [APPLET_META] = META_AID,
};

static const uint8_t AID_Size[] = {
    [APPLET_NULL] = 0,
    [APPLET_PIV] = sizeof(PIV_AID),
    [APPLET_FIDO] = sizeof(FIDO_AID),
    [APPLET_OATH] = sizeof(OATH_AID),
    [APPLET_ADMIN] = sizeof(ADMIN_AID),
    [APPLET_OPENPGP] = sizeof(OPENPGP_AID),
    [APPLET_NDEF] = sizeof(NDEF_AID),
    [APPLET_META] = sizeof(META_AID),
};

static volatile uint32_t buffer_owner = BUFFER_OWNER_NONE;
static uint8_t chaining_buffer[APDU_BUFFER_SIZE];
static CAPDU_CHAINING capdu_chaining = {
    .capdu.data = chaining_buffer,
};
static RAPDU_CHAINING rapdu_chaining = {
    .rapdu.data = chaining_buffer,
};

int build_capdu(CAPDU *capdu, const uint8_t *cmd, uint16_t len) {
  if (len < 4) return -1;
  CLA = cmd[0];
  INS = cmd[1];
  P1 = cmd[2];
  P2 = cmd[3];
  LC = 0;
  LE = 0;

  if (len == 4) // Case 1
    return 0;
  LC = cmd[4];
  if (len == 5) { // Case 2S
    LE = LC;
    LC = 0;
    if (LE == 0) LE = 0x100;
  } else if (LC > 0 && len == 5 + LC) { // Case 3S
    memmove(DATA, cmd + 5, LC);
    LE = 0x100;
  } else if (LC > 0 && len == 6 + LC) { // Case 4S
    memmove(DATA, cmd + 5, LC);
    LE = cmd[5 + LC];
    if (LE == 0) LE = 0x100;
  } else if (len == 7) { // Case 2E
    if (LC != 0) return -1;
    LE = (cmd[5] << 8) | cmd[6];
    if (LE == 0) LE = 0x10000;
  } else {
    if (LC != 0 || len < 7) return -1;
    LC = (cmd[5] << 8) | cmd[6];
    if (LC == 0) return -1;
    if (len == 7 + LC) { // Case 3E
      memmove(DATA, cmd + 7, LC);
      LE = 0x10000;
      return 0;
    } else if (len == 9 + LC) { // Case 4E
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
  } else if (ex->capdu.cla != (sh->cla & 0xEF) || ex->capdu.ins != sh->ins || ex->capdu.p1 != sh->p1 ||
             ex->capdu.p2 != sh->p2) {
    ex->in_chaining = 0;
    goto restart;
  }
  ex->in_chaining = 1;
  if (ex->capdu.lc + sh->lc > APDU_BUFFER_SIZE) return APDU_CHAINING_OVERFLOW;
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

int apdu_output(RAPDU_CHAINING *ex, RAPDU *sh) {
  uint16_t to_send = ex->rapdu.len - ex->sent;
  if (to_send > sh->len) to_send = sh->len;
  memcpy(sh->data, ex->rapdu.data + ex->sent, to_send);
  sh->len = to_send;
  ex->sent += to_send;
  if (ex->sent < ex->rapdu.len) {
    if (ex->rapdu.len - ex->sent > 0xFF)
      sh->sw = 0x61FF;
    else
      sh->sw = 0x6100 + (ex->rapdu.len - ex->sent);
  } else
    sh->sw = ex->rapdu.sw;
  return 0;
}

void process_apdu(CAPDU *capdu, RAPDU *rapdu) {
  int rc;
  if (current_applet == APPLET_PIV) {
    if (INS == PIV_INS_PUT_DATA) {
      LL = 0;
      if (capdu->path[0] == 0) { // first chunk of put data
        piv_process_apdu(capdu, rapdu);
      } else { // not first chunk, append data
        // TODO: check cap
        if ((rc = append_file(capdu->path, DATA, LC)) < 0) {
          ERR_MSG("append file %s error: %d\n", capdu->path, rc);
          SW = SW_UNABLE_TO_PROCESS;
          return;
        }
        DBG_MSG("%s writen length %d\n", capdu->path, get_file_size(capdu->path));
        SW = SW_NO_ERROR;
        if ((CLA & 0x10) == 0) { // last chunk
          capdu->path[0] = 0;
        }
      }
      return;
    }
    if (INS == 0xC0) { // get response, note that metadata is written to rapdu_chaining
      int size = get_file_size(rapdu_chaining.rapdu->path);
      if (size < 0) {
        ERR_MSG("read file size %s error: %d\n", rapdu_chaining.rapdu->path, size);
        LL = 0;
        SW = SW_UNABLE_TO_PROCESS;
        return;
      }
      if ((rc = read_file(rapdu_chaining.rapdu->path, RDATA, rapdu_chaining.rapdu->off, LE)) < 0) {
        ERR_MSG("read file %s error: %d\n", rapdu_chaining.rapdu->path, rc);
        LL = 0;
        SW = SW_UNABLE_TO_PROCESS;
      } else {
        LL = rc;
        rapdu_chaining.rapdu->off += rc;
        int remains = size - rapdu_chaining.rapdu->off;
        if (remains == 0)
          SW = SW_NO_ERROR;
        else if (remains > 0xFF)
          SW = 0x61FF;
        else
          SW = 0x6100 + remains;
      }
      return;
    }
  }
  int ret = apdu_input(&capdu_chaining, capdu);
  if (ret == APDU_CHAINING_NOT_LAST_BLOCK) {
    LL = 0;
    SW = SW_NO_ERROR;
  } else if (ret == APDU_CHAINING_LAST_BLOCK) {
    capdu = &capdu_chaining.capdu;
    LE = MIN(LE, APDU_BUFFER_SIZE);
    if ((CLA == 0x80 || CLA == 0x00) && INS == 0xC0) { // GET RESPONSE
      rapdu->len = LE;
      apdu_output(&rapdu_chaining, rapdu);
      return;
    }
    rapdu_chaining.sent = 0;
    if (CLA == 0x00 && INS == 0xA4 && P1 == 0x04 && P2 == 0x00) {
      uint8_t i, end = APPLET_ENUM_END;
      for (i = APPLET_NULL + 1; i != end; ++i) {
        if (LC >= AID_Size[i] && memcmp(DATA, AID[i], AID_Size[i]) == 0) {
          if (i == APPLET_NDEF && !cfg_is_ndef_enable()) {
            LL = 0;
            SW = SW_FILE_NOT_FOUND;
            DBG_MSG("NDEF is disable\n");
            return;
          }
          if (i != current_applet) applets_poweroff();
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
    switch (current_applet) {
    case APPLET_OPENPGP:
      openpgp_process_apdu(capdu, &rapdu_chaining.rapdu);
      rapdu->len = LE;
      apdu_output(&rapdu_chaining, rapdu);
      break;
    case APPLET_PIV:
      piv_process_apdu(capdu, &rapdu_chaining.rapdu);
      rapdu->len = LE;
      apdu_output(&rapdu_chaining, rapdu);
      break;
    case APPLET_FIDO:
#ifdef TEST
      if (CLA == 0x00 && INS == 0xEE && LC == 0x04 && memcmp(DATA, "\x12\x56\xAB\xF0", 4) == 0) {
        printf("MAGIC REBOOT command received!\r\n");
        ctap_install(0);
        SW = 0x9000;
        LL = 0;
        break;
      }
#endif
      ctap_process_apdu(capdu, &rapdu_chaining.rapdu);
      rapdu->len = LE;
      apdu_output(&rapdu_chaining, rapdu);
      break;
    case APPLET_OATH:
      oath_process_apdu(capdu, rapdu);
      break;
    case APPLET_ADMIN:
      admin_process_apdu(capdu, rapdu);
      break;
    case APPLET_NDEF:
      ndef_process_apdu(capdu, rapdu);
      break;
    case APPLET_META:
      meta_process_apdu(capdu, rapdu);
      break;
    default:
      LL = 0;
      SW = SW_FILE_NOT_FOUND;
    }
  } else {
    LL = 0;
    SW = SW_CHECKING_ERROR;
  }
}

int acquire_apdu_buffer(uint8_t owner) {
  device_atomic_compare_and_swap(&buffer_owner, BUFFER_OWNER_NONE, owner);
  return buffer_owner == owner ? 0 : -1;
}

int release_apdu_buffer(uint8_t owner) {
  device_atomic_compare_and_swap(&buffer_owner, owner, BUFFER_OWNER_NONE);
  return buffer_owner == BUFFER_OWNER_NONE ? 0 : -1;
}
