#include "tusb_option.h"

#if (CFG_TUD_ENABLED && CFG_TUD_VENDOR)
#include "device/usbd.h"
#include "device/usbd_pvt.h"

#include "ccid_device.h"

//--------------------------------------------------------------------+
// MACRO CONSTANT TYPEDEF
//--------------------------------------------------------------------+
typedef struct {
  uint8_t itf_num;
  uint8_t ep_in;
  uint8_t ep_out;

  /*------------- From this point, data is not cleared by bus reset -------------*/
  tu_fifo_t rx_ff;

  uint8_t rx_ff_buf[CFG_TUD_CCID_RX_BUFSIZE];

#if CFG_FIFO_MUTEX
  osal_mutex_def_t rx_ff_mutex;
#endif

  // Endpoint Transfer buffer
  CFG_TUSB_MEM_ALIGN uint8_t epout_buf[CFG_TUD_CCID_EPSIZE];
} ccidd_interface_t;

#define CCIDD_MEM_RESET_SIZE offsetof(ccidd_interface_t, rx_ff)

//--------------------------------------------------------------------+
// INTERNAL OBJECT & FUNCTION DECLARATION
//--------------------------------------------------------------------+
CFG_TUSB_MEM_SECTION static ccidd_interface_t _ccidd_itf[CFG_TUD_CCID];

bool tud_ccid_n_mounted(uint8_t itf) {
  // Return true if the interface is mounted
  return _ccidd_itf[itf].ep_in && _ccidd_itf[itf].ep_out;
}

uint32_t tud_ccid_n_available(uint8_t itf) { return tu_fifo_count(&_ccidd_itf[itf].rx_ff); }

bool tud_ccid_n_peek(uint8_t itf, uint8_t *u8) { return tu_fifo_peek(&_ccidd_itf[itf].rx_ff, u8); }

//--------------------------------------------------------------------+
// Read API
//--------------------------------------------------------------------+
static void _prep_out_transaction(ccidd_interface_t *p_itf) {
  // skip if previous transfer not complete
  if (usbd_edpt_busy(TUD_OPT_RHPORT, p_itf->ep_out)) return;

  // Prepare for incoming data but only allow what we can store in the ring buffer.
  uint16_t max_read = tu_fifo_remaining(&p_itf->rx_ff);
  if (max_read >= CFG_TUD_CCID_EPSIZE) {
    usbd_edpt_xfer(TUD_OPT_RHPORT, p_itf->ep_out, p_itf->epout_buf, CFG_TUD_CCID_EPSIZE);
  }
}

uint32_t tud_ccid_n_read(uint8_t itf, void *buffer, uint32_t bufsize) {
  ccidd_interface_t *p_itf = &_ccidd_itf[itf];
  uint32_t num_read = tu_fifo_read_n(&p_itf->rx_ff, buffer, bufsize);
  _prep_out_transaction(p_itf);
  return num_read;
}

void tud_ccid_n_read_flush(uint8_t itf) {
  ccidd_interface_t *p_itf = &_ccidd_itf[itf];
  tu_fifo_clear(&p_itf->rx_ff);
  _prep_out_transaction(p_itf);
}

//--------------------------------------------------------------------+
// Write API
//--------------------------------------------------------------------+
uint32_t tud_ccid_n_write(uint8_t itf, const void *buffer, uint32_t bufsize) {
  ccidd_interface_t *p_itf = &_ccidd_itf[itf];

  // Skip if usb is not ready yet
  TU_VERIFY(tud_ready(), 0);

  uint8_t const rhport = TUD_OPT_RHPORT;

  // Claim the endpoint
  TU_VERIFY(usbd_edpt_claim(rhport, p_itf->ep_in), 0);

  // Write data to endpoint
  TU_ASSERT(usbd_edpt_xfer(TUD_OPT_RHPORT, p_itf->ep_in, buffer, bufsize), 0);

  return bufsize;
}

//--------------------------------------------------------------------+
// USBD Driver API
//--------------------------------------------------------------------+
void ccidd_reset(uint8_t rhport) {
  (void)rhport;

  for (uint8_t i = 0; i < CFG_TUD_CCID; i++) {
    ccidd_interface_t *p_itf = &_ccidd_itf[i];

    tu_memclr(p_itf, CCIDD_MEM_RESET_SIZE);
    tu_fifo_clear(&p_itf->rx_ff);
  }
}

void ccidd_init(void) {
  tu_memclr(_ccidd_itf, sizeof(_ccidd_itf));

  for (uint8_t i = 0; i < CFG_TUD_CCID; i++) {
    ccidd_interface_t *p_itf = &_ccidd_itf[i];

    // config fifo
    tu_fifo_config(&p_itf->rx_ff, p_itf->rx_ff_buf, CFG_TUD_CCID_RX_BUFSIZE, 1, false);

#if CFG_FIFO_MUTEX
    tu_fifo_config_mutex(&p_itf->rx_ff, NULL, osal_mutex_create(&p_itf->rx_ff_mutex));
#endif
  }
}

uint16_t ccidd_open(uint8_t rhport, tusb_desc_interface_t const *desc_itf, uint16_t max_len) {
  TU_VERIFY(TUSB_CLASS_SMART_CARD == desc_itf->bInterfaceClass, 0);
  TU_VERIFY(0 == desc_itf->bInterfaceSubClass, 0);
  TU_VERIFY(0 == desc_itf->bInterfaceProtocol, 0);

  uint16_t const drv_len = sizeof(tusb_desc_interface_t) + sizeof(tusb_ccid_descriptor_t) +
                           desc_itf->bNumEndpoints * sizeof(tusb_desc_endpoint_t);
  TU_VERIFY(max_len >= drv_len, 0);

  uint8_t const *p_desc = (uint8_t const *)desc_itf;

  // Find available interface
  ccidd_interface_t *p_ccid = NULL;
  for (uint8_t i = 0; i < CFG_TUD_VENDOR; i++) {
    if (_ccidd_itf[i].ep_in == 0 && _ccidd_itf[i].ep_out == 0) {
      p_ccid = &_ccidd_itf[i];
      break;
    }
  }
  TU_VERIFY(p_ccid, 0);

  p_ccid->itf_num = desc_itf->bInterfaceNumber;

  //------------- CCID descriptor -------------//
  p_desc = tu_desc_next(p_desc);
  TU_ASSERT(TUSB_DESC_FUNCTIONAL == tu_desc_type(p_desc), 0);

  //------------- Endpoint Descriptor -------------//
  p_desc = tu_desc_next(p_desc);
  TU_ASSERT(
      usbd_open_edpt_pair(rhport, p_desc, desc_itf->bNumEndpoints, TUSB_XFER_BULK, &p_ccid->ep_out, &p_ccid->ep_in), 0);

  // Prepare for incoming data
  if (p_ccid->ep_out) {
    TU_ASSERT(usbd_edpt_xfer(rhport, p_ccid->ep_out, p_ccid->epout_buf, sizeof(p_ccid->epout_buf)), 0);
  }

  return drv_len;
}

bool ccidd_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *request) {
  // TODO: check if we need to implement ABORT
  // GET_CLOCK_FREQUENCIES and GET_DATA_RATES are not needed
  return true;
}

// The return value is ignored by tud
bool ccidd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) {
  (void)rhport;
  (void)result;

  TU_LOG2("CCIDD: xfer_cb, ep_addr: %d, result: %d, xferred_bytes: %d\n", ep_addr, result, xferred_bytes);

  uint8_t itf = 0;
  ccidd_interface_t *p_itf = _ccidd_itf;

  for (;; itf++, p_itf++) {
    TU_ASSERT(itf < TU_ARRAY_SIZE(_ccidd_itf), false);

    if ((ep_addr == p_itf->ep_out) || (ep_addr == p_itf->ep_in)) break;
  }

  if (ep_addr == p_itf->ep_out) {
    // Receive new data
    tu_fifo_write_n(&p_itf->rx_ff, p_itf->epout_buf, xferred_bytes);

    // Invoke callback
    tud_ccid_rx_cb(itf);

    _prep_out_transaction(p_itf);
  } else if (ep_addr == p_itf->ep_in) {
    // Transmit data to host
    tud_ccid_tx_cb(itf, xferred_bytes);
  }

  return true;
}

//--------------------------------------------------------------------+
// TinyUSB app class driver registration
//--------------------------------------------------------------------+
static usbd_class_driver_t const _ccidd_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init = ccidd_init,
    .reset = ccidd_reset,
    .open = ccidd_open,
    .control_xfer_cb = ccidd_control_xfer_cb,
    .xfer_cb = ccidd_xfer_cb,
    .sof = NULL};

// Implement callback to add our custom driver
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
  *driver_count = 1;
  return &_ccidd_driver;
}

#endif
