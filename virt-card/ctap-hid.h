#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define U2F_HID_CHANNELS  10
#define HID_PACKET_SIZE 64
#define FIDO_U2F_INIT_MSG_HEADER 7
#define FIDO_U2F_CONT_MSG_HEADER 5
#define MAX_PAYLOAD_LEN 7609 // as per u2f-hid-protocol-v1.2 section 2.4
// #define MAX_PAYLOAD_LEN 1024

// Commands
#define FIDO_U2F_HID_PING  (0x80 | 1)
#define FIDO_U2F_HID_MSG  (0x80 | 3)
#define FIDO_U2F_HID_LOCK  (0x80 | 4)
#define FIDO_U2F_HID_INIT  (0x80 | 6)
#define FIDO_U2F_HID_WINK  (0x80 | 8)
#define FIDO_U2F_HID_CBOR  (0x80 | 0x10)
#define FIDO_U2F_HID_CANCEL  (0x80 | 0x11)
#define FIDO_U2F_HID_SYNC  (0x80 | 0x3c)
#define FIDO_U2F_HID_ERROR  (0x80 | 0x3f)

#define FIDO_U2F_ERR_NONE  0
#define FIDO_U2F_ERR_INVALID_CMD  1
#define FIDO_U2F_ERR_INVALID_PAR  2
#define FIDO_U2F_ERR_INVALID_LEN  3
#define FIDO_U2F_ERR_INVALID_SEQ  4
#define FIDO_U2F_ERR_MSG_TIMEOUT  5
#define FIDO_U2F_ERR_CHANNEL_BUSY  6
#define FIDO_U2F_ERR_LOCK_REQUIRED  10
#define FIDO_U2F_ERR_INVALID_CID  11
#define FIDO_U2F_ERR_OTHER  127

#define FIDO_U2FHID_BROADCAST_CID 0xffffffff
#define FIDO_U2FHID_IF_VERSION  2

#define MIN(a,b) ((a)<(b)?(a):(b))

#define DBG_MSG(format, ...) printf("[DBG]%s: " format "\r\n", __func__, ##__VA_ARGS__)
#define INF_MSG(format, ...) printf("[INF]%s: " format "\r\n", __func__, ##__VA_ARGS__)
#define ERR_MSG(format, ...) printf("[ERR]%s: " format "\r\n", __func__, ##__VA_ARGS__)

struct FIDO_U2F_Message_t
{
  uint32_t cid;
  uint8_t cmd;
  uint8_t bcnth;
  uint8_t bcntl;
  uint8_t data[HID_PACKET_SIZE - FIDO_U2F_INIT_MSG_HEADER]; //variable length
};
struct FIDO_U2F_Cont_Message_t
{
  uint32_t cid;
  uint8_t seq;
  uint8_t data[HID_PACKET_SIZE - FIDO_U2F_CONT_MSG_HEADER]; //variable length
};

typedef void (*CTAP_HID_SendReport_t)(uint8_t * buf, int size);
int8_t CTAP_HID_INIT(void);
void CTAP_HID_CheckTimeout();
int8_t CTAP_HID_OutEvent(uint8_t *Report_buf);
int8_t CTAP_HID_InEvent(CTAP_HID_SendReport_t CTAP_HID_SendReport);
