/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _NFC_H_
#define _NFC_H_

#define NFC_CHIP_FM11NC 0
#define NFC_CHIP_FM11NT 1
#define NFC_CHIP_NA -1

#ifndef NFC_CHIP
#define NFC_CHIP NFC_CHIP_NA
#endif

#if NFC_CHIP == NFC_CHIP_FM11NC

#define FM_REG_FIFO_FLUSH    0x1
#define FM_REG_FIFO_WORDCNT  0x2
#define FM_REG_RF_STATUS     0x3
#define FM_REG_RF_TXEN       0x4
#define FM_REG_RF_BAUD       0x5
#define FM_REG_RF_RATS       0x6
#define FM_REG_MAIN_IRQ      0x7
#define FM_REG_FIFO_IRQ      0x8
#define FM_REG_AUX_IRQ       0x9
#define FM_REG_MAIN_IRQ_MASK 0xA
#define FM_REG_FIFO_IRQ_MASK 0xB
#define FM_REG_AUX_IRQ_MASK  0xC
#define FM_REG_NFC_CFG       0xD
#define FM_REG_REGU_CFG      0xE

#define FM_EEPROM_ATQA       0x03A0
#define FM_EEPROM_ATS        0x03B0

#define RF_STATE_MASK 0xE0

#elif NFC_CHIP == NFC_CHIP_FM11NT

#define FM_REG_USER_CFG0     0xFFE0
#define FM_REG_USER_CFG1     0xFFE1
#define FM_REG_USER_CFG2     0xFFE2
#define FM_REG_RESET_SILENCE 0xFFE6
#define FM_REG_STATUS        0xFFE7
#define FM_REG_VOUT_EN_CFG   0xFFE9
#define FM_REG_VOUT_RES_CFG  0xFFEA
#define FM_REG_FIFO_ACCESS   0xFFF0
#define FM_REG_FIFO_FLUSH    0xFFF1
#define FM_REG_FIFO_WORDCNT  0xFFF2
#define FM_REG_RF_STATUS     0xFFF3
#define FM_REG_RF_TXEN       0xFFF4
#define FM_REG_RF_CFG        0xFFF5
#define FM_REG_RF_RATS       0xFFF6
#define FM_REG_MAIN_IRQ      0xFFF7
#define FM_REG_FIFO_IRQ      0xFFF8
#define FM_REG_AUX_IRQ       0xFFF9
#define FM_REG_MAIN_IRQ_MASK 0xFFFA
#define FM_REG_FIFO_IRQ_MASK 0xFFFB
#define FM_REG_AUX_IRQ_MASK  0xFFFC

#define FM_EEPROM_SN         0x0000
#define FM_EEPROM_USER_CFG0  0x0390
#define FM_EEPROM_USER_CFG1  0x0391
#define FM_EEPROM_USER_CFG2  0x0392
#define FM_EEPROM_ATS        0x03B0
#define FM_EEPROM_ATQA       0x03BC
#define FM_EEPROM_CRC8       0x03BB

#endif

#define MAIN_IRQ_AUX (1 << 0)
#define MAIN_IRQ_FIFO (1 << 1)
#define MAIN_IRQ_ARBIT (1 << 2)
#define MAIN_IRQ_TX_DONE (1 << 3)
#define MAIN_IRQ_RX_DONE (1 << 4)
#define MAIN_IRQ_RX_START (1 << 5)
#define MAIN_IRQ_ACTIVE (1 << 6)
#define MAIN_IRQ_RF_ON (1 << 7)

#define FIFO_IRQ_OVERFLOW (1 << 2)
#define FIFO_IRQ_WATER_LEVEL (1 << 3)

#define AUX_IRQ_ERROR_MASK 0x78

#define PCB_MASK 0xC0
#define PCB_I_BLOCK 0x00
#define PCB_R_BLOCK 0x80
#define PCB_S_BLOCK 0xC0
#define PCB_I_CHAINING 0x10

#define R_BLOCK_MASK 0xB2
#define R_ACK 0xA2
#define R_NAK 0xB2

#define S_WTX 0xF2

#define NFC_STATE_IDLE 0x00
#define NFC_STATE_BUSY 0x01

void nfc_init(void);
void nfc_handler(void);
void nfc_loop(void);

#endif // _NFC_H_
