#ifndef __USB_CTAPHID_H
#define __USB_CTAPHID_H

#include <usbd_ioreq.h>

#define USBD_CTAPHID_REPORT_BUF_SIZE 64

#define CTAPHID_REPORT_DESC_SIZE 34

#define CTAPHID_EPIN_ADDR 0x83u
#define CTAPHID_EPIN_SIZE 64

#define CTAPHID_EPOUT_ADDR 0x03u
#define CTAPHID_EPOUT_SIZE 64

#define CTAPHID_DESCRIPTOR_TYPE 0x21
#define CTAPHID_REPORT_DESC 0x22

#define CTAPHID_REQ_SET_PROTOCOL 0x0B
#define CTAPHID_REQ_GET_PROTOCOL 0x03

#define CTAPHID_REQ_SET_IDLE 0x0A
#define CTAPHID_REQ_GET_IDLE 0x02

#define CTAPHID_REQ_SET_REPORT 0x09
#define CTAPHID_REQ_GET_REPORT 0x01

typedef enum { CTAPHID_IDLE = 0, CTAPHID_BUSY } CTAPHID_StateTypeDef;

typedef struct {
  uint8_t Report_buf[USBD_CTAPHID_REPORT_BUF_SIZE];
  uint32_t Protocol;
  uint32_t IdleState;
  uint32_t AltSetting;
  uint32_t IsReportAvailable;
  CTAPHID_StateTypeDef state;
} USBD_CTAPHID_HandleTypeDef;

uint8_t USBD_CTAPHID_Init(USBD_HandleTypeDef *pdev);
uint8_t USBD_CTAPHID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
uint8_t USBD_CTAPHID_DataIn(void);
uint8_t USBD_CTAPHID_DataOut(USBD_HandleTypeDef *pdev);
uint8_t USBD_CTAPHID_EP0_RxReady(void);
uint8_t USBD_CTAPHID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len);

#endif /* __USB_CTAPHID_H */
