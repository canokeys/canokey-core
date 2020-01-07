#include <stdint.h>
#include "device.h"

static void device_delay_us(int us) {
  for (int i = 0; i < us * 1000; ++i)
      asm volatile ("nop");
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
