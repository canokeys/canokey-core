#pragma once

#include <stdint.h>

typedef struct EPType {
  uint8_t addr;        // Endpoint address
  uint8_t index;       // Endpoint index
  uint8_t num;         // Endpoint number
  uint8_t is_in;       // Endpoint direction
  uint8_t is_stall;    // Endpoint stall condition
  uint32_t maxpacket;  // Endpoint Max packet size
  uint8_t *xfer_buff;  // Pointer to transfer buffer
  uint32_t xfer_len;   // Remained transfer length
  uint32_t xfer_count; // Current transfer length
} EPType;

EPType *dummy_get_ep_by_addr(uint8_t addr);


