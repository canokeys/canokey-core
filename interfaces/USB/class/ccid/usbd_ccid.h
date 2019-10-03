#ifndef _USBD_CCID_H_
#define _USBD_CCID_H_

#include <ccid.h>
#include <usbd_ioreq.h>

#define CCID_EPIN_ADDR 0x81
#define CCID_EPIN_SIZE 16

#define CCID_EPOUT_ADDR 0x01
#define CCID_EPOUT_SIZE 16

#define OPENPGP_EPIN_ADDR 0x82
#define OPENPGP_EPIN_SIZE 64

#define OPENPGP_EPOUT_ADDR 0x02
#define OPENPGP_EPOUT_SIZE 64

// CCID Bulk State machine
#define CCID_STATE_IDLE 0
#define CCID_STATE_RECEIVE_DATA 1
#define CCID_STATE_DATA_IN 2

uint8_t USBD_CCID_Init(USBD_HandleTypeDef *pdev);
uint8_t USBD_CCID_DataIn(uint8_t idx);
uint8_t USBD_CCID_DataOut(USBD_HandleTypeDef *pdev, uint8_t idx);
uint8_t CCID_Response_SendData(USBD_HandleTypeDef *pdev, const uint8_t *buf, uint16_t len, uint8_t idx);

#endif // _USBD_CCID_H_
