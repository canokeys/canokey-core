#ifndef _TUSB_CCID_H_
#define _TUSB_CCID_H_

#include "common/tusb_common.h"

#ifndef CFG_TUD_CCID_EPSIZE
#define CFG_TUD_CCID_EPSIZE 64
#endif

#ifdef __cplusplus
extern "C" {
#endif

//--------------------------------------------------------------------+
// Application API (Multiple Interfaces)
//--------------------------------------------------------------------+
bool tud_ccid_n_mounted(uint8_t itf);

uint32_t tud_ccid_n_available(uint8_t itf);
uint32_t tud_ccid_n_read(uint8_t itf, void *buffer, uint32_t bufsize);
bool tud_ccid_n_peek(uint8_t itf, uint8_t *ui8);
void tud_ccid_n_read_flush(uint8_t itf);

uint32_t tud_ccid_n_write(uint8_t itf, const void *buffer, uint32_t bufsize);

//--------------------------------------------------------------------+
// Application API (Single Port)
//--------------------------------------------------------------------+
static inline bool tud_ccid_mounted(void);
static inline uint32_t tud_ccid_available(void);
static inline uint32_t tud_ccid_read(void *buffer, uint32_t bufsize);
static inline bool tud_ccid_peek(uint8_t *ui8);
static inline void tud_ccid_read_flush(void);
static inline uint32_t tud_ccid_write(const void *buffer, uint32_t bufsize);

//--------------------------------------------------------------------+
// Application Callback API (weak is optional)
//--------------------------------------------------------------------+

// Invoked when received new data
TU_ATTR_WEAK void tud_ccid_rx_cb(uint8_t itf);

// Invoked when last rx transfer finished
TU_ATTR_WEAK void tud_ccid_tx_cb(uint8_t itf, uint32_t sent_bytes);

//--------------------------------------------------------------------+
// Inline Functions
//--------------------------------------------------------------------+

static inline bool tud_ccid_mounted(void) { return tud_ccid_n_mounted(0); }

static inline uint32_t tud_ccid_available(void) { return tud_ccid_n_available(0); }

static inline uint32_t tud_ccid_read(void *buffer, uint32_t bufsize) { return tud_ccid_n_read(0, buffer, bufsize); }

static inline bool tud_ccid_peek(uint8_t *ui8) { return tud_ccid_n_peek(0, ui8); }

static inline void tud_ccid_read_flush(void) { tud_ccid_n_read_flush(0); }

static inline uint32_t tud_ccid_write(const void *buffer, uint32_t bufsize) {
  tud_ccid_n_write(0, buffer, bufsize);
}

//--------------------------------------------------------------------+
// Internal Class Driver API
//--------------------------------------------------------------------+
void ccidd_init(void);
void ccidd_reset(uint8_t rhport);
uint16_t ccidd_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len);
bool ccidd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t event, uint32_t xferred_bytes);

//--------------------------------------------------------------------+
// USB CCID Descriptor
//--------------------------------------------------------------------+
typedef struct TU_ATTR_PACKED {
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint16_t bcdCCID;
  uint8_t bMaxSlotIndex;
  uint8_t bVoltageSupport;
  uint32_t dwProtocols;
  uint32_t dwDefaultClock;
  uint32_t dwMaximumClock;
  uint8_t bNumClockSupported;
  uint32_t dwDataRate;
  uint32_t dwMaxDataRate;
  uint8_t bNumDataRatesSupported;
  uint32_t dwMaxIFSD;
  uint32_t dwSynchProtocols;
  uint32_t dwMechanical;
  uint32_t dwFeatures;
  uint32_t dwMaxCCIDMessageLength;
  uint8_t bClassGetResponse;
  uint8_t bClassEnvelope;
  uint16_t wLcdLayout;
  uint8_t bPINSupport;
  uint8_t bMaxCCIDBusySlots;
} tusb_ccid_descriptor_t;

#ifdef __cplusplus
}
#endif

#endif /* _TUSB_CCID_H_ */