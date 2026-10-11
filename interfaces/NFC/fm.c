// SPDX-License-Identifier: Apache-2.0
#include "device.h"

#if ENABLE_NFC

#include <stdint.h>

#if NFC_CHIP == NFC_CHIP_FM11NT
static void device_delay_us(int us) {
  for (int i = 0; i < us * 10; ++i)
    asm volatile("nop");
}
#endif

fm_status_t fm_read_regs(uint16_t reg, uint8_t *buf, uint8_t len) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  return fm11nt_read(reg, buf, len);
#else
  (void)reg;
  (void)buf;
  (void)len;
  return FM_STATUS_NACK;
#endif
}

fm_status_t fm_write_regs(uint16_t reg, const uint8_t *buf, uint8_t len) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  return fm11nt_write(reg, buf, len);
#else
  (void)reg;
  (void)buf;
  (void)len;
  return FM_STATUS_NACK;
#endif
}

fm_status_t fm_read_eeprom(uint16_t addr, uint8_t *buf, uint8_t len) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  return fm11nt_read(addr, buf, len);
#else
  (void)addr;
  (void)buf;
  (void)len;
  return FM_STATUS_NACK;
#endif
}

fm_status_t fm_write_eeprom(uint16_t addr, const uint8_t *buf, uint8_t len) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  const fm_status_t ret = fm11nt_write(addr, buf, len);
  device_delay(10);
  return ret;
#else
  (void)addr;
  (void)buf;
  (void)len;
  return FM_STATUS_NACK;
#endif
}

fm_status_t fm_read_fifo(uint8_t *buf, uint8_t len) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  return fm11nt_read(FM_REG_FIFO_ACCESS, buf, len);
#else
  (void)buf;
  (void)len;
  return FM_STATUS_NACK;
#endif
}

fm_status_t fm_write_fifo(uint8_t *buf, uint8_t len) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  return fm11nt_write(FM_REG_FIFO_ACCESS, buf, len);
#else
  (void)buf;
  (void)len;
  return FM_STATUS_NACK;
#endif
}

void fm11_init(void) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  uint8_t crc_buffer[13];
  const uint8_t user_cfg[] = {0x91, 0x80, 0x21, 0xCF};
  const uint8_t atqa_sak[] = {0x44, 0x00, 0x04, 0x20};
  const uint8_t ats[] = {0x05, 0x72, 0xA0, 0x57, 0x00, 0x99, 0x00};
  fm_csn_low();
  device_delay_us(500);
  fm_write_eeprom(FM_EEPROM_USER_CFG0, user_cfg, sizeof(user_cfg));
  fm_write_eeprom(FM_EEPROM_ATS, ats, sizeof(ats));
  fm_write_eeprom(FM_EEPROM_ATQA, atqa_sak, sizeof(atqa_sak));
  fm_read_eeprom(FM_EEPROM_SN, crc_buffer, 9);
  DBG_MSG("SN: ");
  PRINT_HEX(crc_buffer, 9);
  memcpy(crc_buffer + 9, atqa_sak, sizeof(atqa_sak));
  const uint8_t crc8 = fm_crc8(crc_buffer, sizeof(crc_buffer));
  fm_write_eeprom(FM_EEPROM_CRC8, &crc8, 1);
  fm_csn_high();
#endif
}

#if NFC_CHIP == NFC_CHIP_FM11NT

#define I2C_WRITE_WITH_CHECK(data)                                                                                     \
  do {                                                                                                                 \
    if (i2c_write_byte(data) == FM_STATUS_NACK) return FM_STATUS_NACK;                                                 \
  } while (0)

#define I2C_ADDR 0x57

fm_status_t fm11nt_read(uint16_t addr, uint8_t *buf, uint8_t len) {
  if (len == 0) return FM_STATUS_OK;

  uint8_t slave_id = (I2C_ADDR << 1) | 0;
  i2c_start();
  I2C_WRITE_WITH_CHECK(slave_id);

  // set reg/eeprom addr
  I2C_WRITE_WITH_CHECK(addr >> 8);
  I2C_WRITE_WITH_CHECK(addr & 0xFF);

  // switch to read mode
  slave_id |= 1;
  i2c_start();
  I2C_WRITE_WITH_CHECK(slave_id);

  // master transmit
  for (uint8_t k = 0; k < len; k++) {
    buf[k] = i2c_read_byte();
    if (k == len - 1) {
      // master sends NACK to slave
      i2c_send_nack();
      // Generate STOP condition
      i2c_stop();
      break;
    } else {
      // master sends ACK to slave
      i2c_send_ack();
    }
    // wait to receive next byte from slave
    scl_delay();
  }

  return FM_STATUS_OK;
}

fm_status_t fm11nt_write(const uint16_t addr, const uint8_t *buf, const uint8_t len) {
  const uint8_t slave_id = (I2C_ADDR << 1) | 0;
  i2c_start();
  I2C_WRITE_WITH_CHECK(slave_id);

  // set reg/eeprom addr
  I2C_WRITE_WITH_CHECK(addr >> 8);
  I2C_WRITE_WITH_CHECK(addr & 0xFF);

  // master transmit
  for (size_t i = 0; i < len; i++) {
    // master write a byte to salve and check ACK signal
    I2C_WRITE_WITH_CHECK(buf[i]);
  }
  i2c_stop();

  return FM_STATUS_OK;
}

uint8_t fm_crc8(const uint8_t *data, const uint8_t data_length) {
  int crc8 = 0xff;
  for (uint8_t i = 0; i < data_length; i++) {
    crc8 ^= data[i];
    for (int j = 0; j < 8; j++) {
      if ((crc8 & 0x01) == 0x01)
        crc8 = (crc8 >> 1) ^ 0xb8;
      else
        crc8 >>= 1;
      crc8 &= 0xff;
    }
  }
  return crc8 & 0xff;
}

#endif // NFC_CHIP == NFC_CHIP_FM11NT

#endif // ENABLE_NFC
