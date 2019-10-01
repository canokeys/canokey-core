#ifndef __CTAPHID_H_INCLUDED__
#define __CTAPHID_H_INCLUDED__

#include <common.h>

#define HID_RPT_SIZE 64 // Default size of raw HID report

// Frame layout - command- and continuation frames

#define CID_BROADCAST 0xffffffff // Broadcast channel id
#define TYPE_MASK 0x80           // Frame type mask
#define TYPE_INIT 0x80           // Initial frame identifier
#define TYPE_CONT 0x00           // Continuation frame identifier

typedef struct {
  uint32_t cid; // Channel identifier
  union {
    uint8_t type; // Frame type - b7 defines type
    struct {
      uint8_t cmd;                    // Command - b7 set
      uint8_t bcnth;                  // Message byte count - high part
      uint8_t bcntl;                  // Message byte count - low part
      uint8_t data[HID_RPT_SIZE - 7]; // Data payload
    } init;
    struct {
      uint8_t seq;                    // Sequence number - b7 cleared
      uint8_t data[HID_RPT_SIZE - 5]; // Data payload
    } cont;
  };
} CTAPHID_FRAME;

#define FRAME_TYPE(f) ((f).type & TYPE_MASK)
#define FRAME_CMD(f) ((f).init.cmd & ~TYPE_MASK)
#define MSG_LEN(f) ((f).init.bcnth * 256 + (f).init.bcntl)
#define FRAME_SEQ(f) ((f).cont.seq & ~TYPE_MASK)

// General constants

#define CTAPHID_IF_VERSION 2      // Current interface implementation version
#define CTAPHID_TRANS_TIMEOUT 800 // Default message timeout in ms

// CTAPHID native commands

#define CTAPHID_PING (TYPE_INIT | 0x01)
#define CTAPHID_MSG (TYPE_INIT | 0x03)
#define CTAPHID_LOCK (TYPE_INIT | 0x04)
#define CTAPHID_INIT (TYPE_INIT | 0x06)
#define CTAPHID_WINK (TYPE_INIT | 0x08)
#define CTAPHID_CBOR (TYPE_INIT | 0x10)
#define CTAPHID_CANCEL (TYPE_INIT | 0x11)
#define CTAPHID_KEEPALIVE (TYPE_INIT | 0x3b)
#define CTAPHID_ERROR (TYPE_INIT | 0x3f)

// CTAPHID_INIT command defines

#define INIT_NONCE_SIZE 8 // Size of channel initialization challenge

#define CAPABILITY_WINK 0x01
#define CAPABILITY_CBOR 0x04
#define CAPABILITY_NMSG 0x08

typedef struct {
  uint8_t nonce[INIT_NONCE_SIZE]; // Client application nonce
} CTAPHID_INIT_REQ;

typedef struct {
  uint8_t nonce[INIT_NONCE_SIZE]; // Client application nonce
  uint32_t cid;                   // Channel identifier
  uint8_t versionInterface;       // Interface version
  uint8_t versionMajor;           // Major version number
  uint8_t versionMinor;           // Minor version number
  uint8_t versionBuild;           // Build version number
  uint8_t capFlags;               // Capabilities flags
} __packed CTAPHID_INIT_RESP;

// Low-level error codes. Return as negatives.

#define ERR_NONE 0x00          // No error
#define ERR_INVALID_CMD 0x01   // Invalid command
#define ERR_INVALID_PAR 0x02   // Invalid parameter
#define ERR_INVALID_LEN 0x03   // Invalid message length
#define ERR_INVALID_SEQ 0x04   // Invalid message sequencing
#define ERR_MSG_TIMEOUT 0x05   // Message has timed out
#define ERR_CHANNEL_BUSY 0x06  // Channel busy
#define ERR_LOCK_REQUIRED 0x0a // Command requires channel lock
#define ERR_INVALID_CID 0x0b
#define ERR_OTHER 0x7f // Other unspecified error

#define LOOP_SUCCESS 0x00
#define LOOP_CANCEL 0x01

#define MAX_CTAP_BUFSIZE 1280

typedef struct {
  uint32_t cid;
  uint16_t bcnt_total;
  uint16_t bcnt_current;
  uint32_t expire;
  uint8_t state;
  uint8_t cmd;
  uint8_t seq;
  alignas(4) uint8_t data[MAX_CTAP_BUFSIZE];
} CTAPHID_Channel;

uint8_t CTAPHID_Init(void);
uint8_t CTAPHID_OutEvent(uint8_t *data);
void CTAPHID_SendResponse(uint32_t cid, uint8_t cmd, uint8_t *data, uint16_t len);
uint8_t CTAPHID_Loop(uint8_t wait_for_user);

#endif // __CTAPHID_H_INCLUDED__
