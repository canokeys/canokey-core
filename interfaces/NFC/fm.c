// SPDX-License-Identifier: Apache-2.0
#include "device.h"
#include <stdint.h>

#if _NFC_CHIP == NFC_CHIP_FM11NC

static void device_delay_us(int us) {
  for (int i = 0; i < us * 10; ++i)
    asm volatile("nop");
}

void fm_read_reg(uint8_t reg, uint8_t *buf, uint8_t len) {
  fm_nss_low();
  reg |= 0x20;
  fm_transmit(&reg, 1);
  fm_receive(buf, len);
  fm_nss_high();
}

void fm_write_reg(uint8_t reg, uint8_t *buf, uint8_t len) {
  fm_nss_low();
  fm_transmit(&reg, 1);
  fm_transmit(buf, len);
  fm_nss_high();
}

void fm_read_eeprom(uint16_t addr, uint8_t *buf, uint8_t len) {
  fm_nss_low();
  device_delay_us(100);
  uint8_t data[2] = {0x60 | (addr >> 8), addr & 0xFF};
  fm_transmit(data, 2);
  fm_receive(buf, len);
  fm_nss_high();
}

void fm_write_eeprom(uint16_t addr, uint8_t *buf, uint8_t len) {
  fm_nss_low();
  device_delay_us(100);
  uint8_t data[2] = {0xCE, 0x55};
  fm_transmit(data, 2);
  fm_nss_high();

  device_delay_us(100);

  fm_nss_low();
  data[0] = 0x40 | (addr >> 8);
  data[1] = addr & 0xFF;
  fm_transmit(data, 2);
  fm_transmit(buf, len);
  fm_nss_high();
}

void fm_read_fifo(uint8_t *buf, uint8_t len) {
  fm_nss_low();
  uint8_t addr = 0xA0;
  fm_transmit(&addr, 1);
  fm_receive(buf, len);
  fm_nss_high();
}

void fm_write_fifo(uint8_t *buf, uint8_t len) {
  fm_nss_low();
  uint8_t addr = 0x80;
  fm_transmit(&addr, 1);
  fm_transmit(buf, len);
  fm_nss_high();
}

#elif _NFC_CHIP == NFC_CHIP_FM11NT

#define I2C_ADDR 0x57

void fm_read(uint16_t addr, uint8_t *buf, uint8_t len) {
  uint8_t slave_id = (I2C_ADDR << 1) | 0;
  i2c_start();
  i2c_write_byte(slave_id);

  // set reg/eeprom addr
  i2c_write_byte(addr >> 8);
  i2c_write_byte(addr & 0xFF);

  // switch to read mode
  slave_id |= 1;
  i2c_start();
  i2c_write_byte(slave_id);

  // master transmit
  for (size_t k = 0; k < len; k++) {
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
}

void fm_write(uint16_t addr, const uint8_t *buf, uint8_t len) {
  const uint8_t slave_id = (I2C_ADDR << 1) | 0;
  i2c_start();
  i2c_write_byte(slave_id);

  // set reg/eeprom addr
  i2c_write_byte(addr >> 8);
  i2c_write_byte(addr & 0xFF);

  // master transmit
  for (size_t i = 0; i < len; i++) {
    // master write a byte to salve and check ACK signal
    i2c_write_byte(buf[i]);
  }
  i2c_stop();
}

uint8_t fm_crc8(const uint8_t *data, const uint8_t data_length) {
  int crc8 = 0xff;
  for (int i = 0; i < data_length; i++) {
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


#endif