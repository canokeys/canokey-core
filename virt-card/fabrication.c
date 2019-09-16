#include "fabrication.h"
#include "piv.h"
#include "u2f.h"
#include "openpgp.h"
#include "oath.h"
#include <admin.h>
#include <aes.h>
#include <apdu.h>
#include <emubd/lfs_emubd.h>
#include <fs.h>
#include <lfs.h>

static struct lfs_config cfg;
static lfs_emubd_t bd;

uint8_t private_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
uint8_t cert[] = {0x30,0x82,0x01,0x1f,0x30,0x81,0xc8,0x02,0x09,0x00,0x92,0xce,0x92,0x23,0xe6,0xf2,0xf5,0x1f,0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,
              0x30,0x19,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x43,0x4e,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x0c,0x01,0x55,0x30,0x1e,0x17,
              0x0d,0x31,0x39,0x30,0x37,0x31,0x36,0x31,0x32,0x31,0x36,0x34,0x35,0x5a,0x17,0x0d,0x31,0x39,0x30,0x38,0x31,0x35,0x31,0x32,0x31,0x36,0x34,0x35,0x5a,0x30,
              0x19,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x43,0x4e,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x0c,0x01,0x55,0x30,0x59,0x30,0x13,
              0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x7a,0x59,0x31,0x80,0x86,0x0c,0x40,
              0x37,0xc8,0x3c,0x12,0x74,0x98,0x45,0xc8,0xee,0x14,0x24,0xdd,0x29,0x7f,0xad,0xcb,0x89,0x5e,0x35,0x82,0x55,0xd2,0xc7,0xd2,0xb2,0xa8,0xca,0x25,0x58,0x0f,
              0x26,0x26,0xfe,0x57,0x90,0x62,0xff,0x1b,0x99,0xff,0x91,0xc2,0x4a,0x0d,0xa0,0x6f,0xb3,0x2b,0x5b,0xe2,0x01,0x48,0xc9,0x24,0x9f,0x56,0x50,0x30,0x0a,0x06,
              0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x03,0x46,0x00,0x30,0x43,0x02,0x1f,0x5f,0x4f,0xb4,0xa1,0xd9,0xbd,0xe2,0xc2,0x41,0x4f,0xed,0x58,0x73,0xc1,
              0xe5,0x9b,0x95,0x6d,0xaf,0x4c,0x8c,0xb9,0x47,0x42,0x01,0xf6,0xb1,0x89,0x11,0xdd,0x13,0x02,0x20,0x18,0xb7,0xb3,0x43,0xf9,0x83,0xe8,0x77,0x60,0xee,0x06,
              0x78,0xea,0x1e,0xde,0xd0,0x01,0xc3,0xd7,0x87,0x6d,0xae,0xcf,0xde,0xaf,0xa9,0x4b,0xe1,0xfb,0xd2,0xbc,0x9a,};

static void fake_u2f_personalization() {

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU capdu;
  RAPDU rapdu;
  capdu.data = c_buf;
  rapdu.data = r_buf;

  apdu_fill_with_command(&capdu, "00 20 00 00 06 31 32 33 34 35 36");
  admin_process_apdu(&capdu, &rapdu);

  capdu.cla = 0x00;
  capdu.ins = ADMIN_INS_WRITE_U2F_PRIVATE_KEY;
  capdu.data = private_key;
  capdu.lc = 32;

  admin_process_apdu(&capdu, &rapdu);

  capdu.ins = ADMIN_INS_WRITE_U2F_CERT;
  capdu.data = cert;
  capdu.lc = sizeof(cert);
  admin_process_apdu(&capdu, &rapdu);
}

static void fido2_init() {
  uint8_t buf[32];
  random_buffer(buf, 32);
  write_file("ctap_cert", NULL, 0);
  write_attr("ctap_cert", 0x00, buf, 32);
  write_attr("ctap_cert", 0x01, buf, 4);
}


int card_fabrication_procedure() {
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_emubd_read;
  cfg.prog = &lfs_emubd_prog;
  cfg.erase = &lfs_emubd_erase;
  cfg.sync = &lfs_emubd_sync;
  cfg.read_size = 1;
  cfg.prog_size = 512;
  cfg.block_size = 512;
  cfg.block_count = 256;
  cfg.block_cycles = 50000;
  cfg.cache_size = 512;
  cfg.lookahead_size = 16;
  lfs_emubd_create(&cfg, "lfs-root");

  fs_init(&cfg);
  admin_install();
  oath_install(0);
  u2f_config(16, aes128_enc, aes128_dec);
  fake_u2f_personalization();

  fido2_init();

  static uint8_t piv_buffer[2048];
  piv_config(piv_buffer, sizeof(piv_buffer));
  piv_install(0);

  openpgp_install(0);
  return 0;
}
