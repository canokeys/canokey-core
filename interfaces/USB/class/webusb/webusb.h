#ifndef _WEBUSB_H_
#define _WEBUSB_H_

#include <usbd_ioreq.h>

#define WEBUSB_EP0_SENDER 0x01

#define WEBUSB_REQ_CMD 0x00
#define WEBUSB_REQ_CALC 0x01
#define WEBUSB_REQ_RESP 0x02
#define WEBUSB_REQ_STAT 0x03

#define WEBUSB_REQ_FIRST_PACKET 0x4000
#define WEBUSB_REQ_MORE_PACKET 0x8000

uint8_t USBD_WEBUSB_Init(USBD_HandleTypeDef *pdev);
uint8_t USBD_WEBUSB_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
uint8_t USBD_WEBUSB_TxSent(USBD_HandleTypeDef *pdev);
void WebUSB_Loop(void);

#endif // _WEBUSB_H_
