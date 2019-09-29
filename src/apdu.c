#include <apdu.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void copy_data(uint8_t *buf, char **cmd, int lc) {
  for (int i = 0; i < lc; ++i)
    *buf++ = strtoul(*cmd, cmd, 16);
}

void apdu_fill_with_command(CAPDU *capdu, char *cmd) {
  int txLen = (strlen(cmd) + 1) / 3;
  CLA = strtoul(cmd, &cmd, 16);
  INS = strtoul(cmd, &cmd, 16);
  P1 = strtoul(cmd, &cmd, 16);
  P2 = strtoul(cmd, &cmd, 16);
  LC = 0;
  LE = 0;

  if (txLen == 4) // Case 1
    return;
  LC = strtoul(cmd, &cmd, 16);
  if (txLen == 5) { // Case 2S
    LE = LC;
    LC = 0;
  } else if (LC > 0 && txLen == 5 + LC) { // Case 3S
    copy_data(DATA, &cmd, LC);
  } else if (LC > 0 && txLen == 6 + LC) { // Case 4S
    copy_data(DATA, &cmd, LC);
    LE = strtoul(cmd, &cmd, 16);
    if (LE == 0) LE = 0x100;
  } else if (txLen == 7) { // Case 2E
    assert(LC == 0);
    LE = strtoul(cmd, &cmd, 16);
    LE = (LE << 8u) + strtoul(cmd, &cmd, 16);
  } else {
    assert(LC == 0);
    LC = strtoul(cmd, &cmd, 16);
    LC = (LC << 8u) + strtoul(cmd, &cmd, 16);
    assert(LC > 0);
    copy_data(DATA, &cmd, LC);
    if (txLen == 7 + LC) { // Case 3E
      return;
    } else if (txLen == 9 + LC) { // Case 4E
      LE = strtoul(cmd, &cmd, 16);
      LE = (LE << 8u) + strtoul(cmd, &cmd, 16);
      if (LE == 0) LE = 0x10000;
    } else {
      assert(0);
    }
  }
}

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
    memcpy(DATA, cmd + 5, LC);
    LE = 0x100;
  } else if (LC > 0 && len == 6 + LC) { // Case 4S
    memcpy(DATA, cmd + 5, LC);
    LE = cmd[5 + LC];
    if (LE == 0) LE = 0x100;
  } else if (len == 7) { // Case 2E
    if (LC != 0) return -1;
    LE = (cmd[5] << 8) | cmd[6];
    if (LE == 0) LE = 0x10000;
  } else {
    if (LC != 0) return -1;
    LC = (cmd[5] << 8) | cmd[6];
    if (LC == 0) return -1;
    memcpy(DATA, cmd + 7, LC);
    if (len == 7 + LC) { // Case 3E
      LE = 0x10000;
      return 0;
    } else if (len == 9 + LC) { // Case 4E
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
  if (ex->capdu.lc + sh->lc > ex->max_size) return APDU_CHAINING_OVERFLOW;
  memcpy(ex->capdu.data + ex->capdu.lc, sh->data, sh->lc);
  ex->capdu.lc += sh->lc;

  if (sh->cla & 0x10) // not last block
    return APDU_CHAINING_NOT_LAST_BLOCK;
  else {
    ex->in_chaining = 0;
    return APDU_CHAINING_LAST_BLOCK;
  }
}

int apdu_output(RAPDU_CHAINING *ex, RAPDU *sh) {
  uint16_t to_send = ex->rapdu.len - ex->sent;
  // if (to_send == 0) return APDU_CHAINING_NO_MORE;
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
