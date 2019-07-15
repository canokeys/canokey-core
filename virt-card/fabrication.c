#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include "fabrication.h"
#include "u2f.h"
#include "core.h"
#include <aes.h>
#include <apdu.h>
#include <ecdsa.h>
#include <emubd/lfs_emubd.h>
#include <lfs.h>
#include <memzero.h>
#include <sha2.h>
#include <util.h>


uint8_t public_key[] = {
    0x04, 0x7A, 0x59, 0x31, 0x80, 0x86, 0x0C, 0x40, 0x37, 0xC8, 0x3C,
    0x12, 0x74, 0x98, 0x45, 0xC8, 0xEE, 0x14, 0x24, 0xDD, 0x29, 0x7F,
    0xAD, 0xCB, 0x89, 0x5E, 0x35, 0x82, 0x55, 0xD2, 0xC7, 0xD2, 0xB2,
    0xA8, 0xCA, 0x25, 0x58, 0x0F, 0x26, 0x26, 0xFE, 0x57, 0x90, 0x62,
    0xFF, 0x1B, 0x99, 0xFF, 0x91, 0xC2, 0x4A, 0x0D, 0xA0, 0x6F, 0xB3,
    0x2B, 0x5B, 0xE2, 0x01, 0x48, 0xC9, 0x24, 0x9F, 0x56, 0x50};

static void fake_u2f_personalization() {

  uint8_t c_buf[100], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x80;
  capdu->ins = U2F_PERSONALIZATION;
  capdu->lc = 0;

  u2f_process_apdu(capdu, rapdu);

  uint8_t key_buf[112];
  read_file(&g_lfs, "u2f_key", key_buf, sizeof(key_buf));
  memzero(key_buf + 96, 16);
  write_file(&g_lfs, "u2f_key", key_buf, sizeof(key_buf));

  capdu->ins = U2F_INSTALL_CERT;
  capdu->lc = 1;
  capdu->data[0] = 0xDD;
  u2f_process_apdu(capdu, rapdu);
}


int u2f_fabrication_procedure() {
  struct lfs_config cfg;
  lfs_emubd_t bd;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_emubd_read;
  cfg.prog = &lfs_emubd_prog;
  cfg.erase = &lfs_emubd_erase;
  cfg.sync = &lfs_emubd_sync;
  cfg.read_size = 16;
  cfg.prog_size = 16;
  cfg.block_size = 512;
  cfg.block_count = 400;
  cfg.block_cycles = 50000;
  cfg.cache_size = 128;
  cfg.lookahead_size = 16;
  lfs_emubd_create(&cfg, "test");

  init(&cfg);

  fake_u2f_personalization();
  return 0;
}
