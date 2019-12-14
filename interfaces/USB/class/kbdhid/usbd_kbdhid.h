#ifndef __USB_KBDHID_H
#define __USB_KBDHID_H

#include <usbd_ioreq.h>

#define KBDHID_DESCRIPTOR_TYPE 0x21
#define KBDHID_REPORT_DESC 0x22
#define KBDHID_REQ_SET_IDLE 0x0A
#define USBD_KBDHID_REPORT_BUF_SIZE 8
#define KBDHID_REPORT_DESC_SIZE 63

typedef enum { KBDHID_IDLE = 0, KBDHID_BUSY } KBDHID_StateTypeDef;

typedef struct {
  uint8_t report_buf[USBD_KBDHID_REPORT_BUF_SIZE];
  uint32_t idle_state;
  KBDHID_StateTypeDef state;
} USBD_KBDHID_HandleTypeDef;

typedef struct {
  uint8_t modifier;
  uint8_t reserved;
  uint8_t keycode[6];
} keyboard_report_t;

uint8_t USBD_KBDHID_Init(USBD_HandleTypeDef *pdev);
uint8_t USBD_KBDHID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
uint8_t USBD_KBDHID_DataIn(void);
uint8_t USBD_KBDHID_DataOut(USBD_HandleTypeDef *pdev);
uint8_t USBD_KBDHID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len);
uint8_t USBD_KBDHID_IsIdle(void);

#endif /* __USB_KBDHID_H */
