#ifndef _USBD_CCID_H_
#define _USBD_CCID_H_

#include <usbd_ioreq.h>

#define CCID_EPIN_ADDR 0x82
#define CCID_EPIN_SIZE 64

#define CCID_EPOUT_ADDR 0x02
#define CCID_EPOUT_SIZE 64

// CCID Bulk State machine
#define CCID_STATE_IDLE 0
#define CCID_STATE_RECEIVE_DATA 1
#define CCID_STATE_DATA_IN 2

#define ABDATA_SIZE 2000
#define CCID_CMD_HEADER_SIZE 10
#define CCID_NUMBER_OF_SLOTS 1

uint8_t USBD_CCID_Init(USBD_HandleTypeDef *pdev);
uint8_t USBD_CCID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
uint8_t USBD_CCID_DataIn(void);
uint8_t USBD_CCID_DataOut(USBD_HandleTypeDef *pdev);
uint8_t CCID_Response_SendData(USBD_HandleTypeDef *pdev, const uint8_t *buf, uint16_t len);

#endif // _USBD_CCID_H_
