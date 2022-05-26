#ifndef _TUSB_CCID_H_
#define _TUSB_CCID_H_

#include <tusb.h>

// CCID Bulk State machine
typedef enum {
  CCID_STATE_IDLE,
  CCID_STATE_RECEIVE_DATA,
  CCID_STATE_DATA_IN,
  CCID_STATE_DATA_IN_WITH_ZLP,
  CCID_STATE_PROCESS_DATA,
} ccidd_state_e;

typedef struct {
  volatile ccidd_state_e state;

  uint8_t itf_num;
  uint8_t rhport;
  uint8_t ep_bulk_in;
  uint8_t ep_bulk_out;

  CFG_TUSB_MEM_ALIGN uint8_t epin_buf[CFG_TUD_CCIDD_EP_BUFSIZE];
  CFG_TUSB_MEM_ALIGN uint8_t epout_buf[CFG_TUD_CCIDD_EP_BUFSIZE];
} ccidd_interface_state_t;

/// USB CCID Descriptor
typedef struct TU_ATTR_PACKED {
  uint8_t  bLength;
  uint8_t  bDescriptorType;
  uint16_t bcdCCID;
  uint8_t  bMaxSlotIndex;
  uint8_t  bVoltageSupport;
  uint32_t dwProtocols;
  uint32_t dwDefaultClock;
  uint32_t dwMaximumClock;
  uint8_t  bNumClockSupported;
  uint32_t dwDataRate;
  uint32_t dwMaxDataRate;
  uint8_t  bNumDataRatesSupported;
  uint32_t dwMaxIFSD;
  uint32_t dwSynchProtocols;
  uint32_t dwMechanical;
  uint32_t dwFeatures;
  uint32_t dwMaxCCIDMessageLength;
  uint8_t  bClassGetResponse;
  uint8_t  bClassEnvelope;
  uint16_t wLcdLayout;
  uint8_t  bPINSupport;
  uint8_t  bMaxCCIDBusySlots;
} tusb_ccid_descriptor_t;


#endif /* _TUSB_CCID_H_ */