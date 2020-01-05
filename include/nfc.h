#ifndef _NFC_H_
#define _NFC_H_

#define REG_FIFO_FLUSH 0x1
#define REG_FIFO_WORDCNT 0x2
#define REG_RF_STATUS 0x3
#define REG_RF_TXEN 0x4
#define REG_RF_BAUD 0x5
#define REG_RF_RATS 0x6
#define REG_MAIN_IRQ 0x7
#define REG_FIFO_IRQ 0x8
#define REG_AUX_IRQ 0x9
#define REG_MAIN_IRQ_MASK 0xA
#define REG_FIFO_IRQ_MASK 0xB
#define REG_AUX_IRQ_MASK 0xC
#define REG_NFC_CFG 0xD
#define REG_REGU_CFG 0xE

#define RF_STATE_MASK 0xE0
#define RF_STATE_L4 0xA0

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

#define AUX_IRQ_ERROR_MASK 0x1C

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
int nfc_has_rf(void);
void nfc_handler(void);
void nfc_loop(void);
void nfc_wtx(void);

#endif // _NFC_H_
