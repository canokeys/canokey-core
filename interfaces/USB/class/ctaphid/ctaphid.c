// SPDX-License-Identifier: Apache-2.0
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <rand.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>

static CTAPHID_FRAME frame;
static CTAPHID_Channel channel;
static volatile uint8_t has_frame;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static uint8_t (*callback_send_report)(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len);

const uint16_t ISIZE = sizeof(frame.init.data);
const uint16_t CSIZE = sizeof(frame.cont.data);

uint8_t CTAPHID_Init(uint8_t (*send_report)(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len)) {
  callback_send_report = send_report;
  channel.state = CTAPHID_IDLE;
  has_frame = 0;
  return 0;
}

uint8_t CTAPHID_OutEvent(uint8_t *data) {
  if (has_frame) {
    ERR_MSG("overrun\n");
    return 0;
  }
  memcpy(&frame, data, sizeof(frame));
  has_frame = 1;
  return 0;
}

static void CTAPHID_SendFrame(void) { callback_send_report(&usb_device, (uint8_t *)&frame, sizeof(CTAPHID_FRAME)); }

static void CTAPHID_SendResponse(uint32_t cid, uint8_t cmd, uint8_t *data, uint16_t len) {
  uint16_t off = 0;
  size_t copied;
  uint8_t seq = 0;

  memset(&frame, 0, sizeof(frame));
  frame.cid = cid;
  frame.type = TYPE_INIT;
  frame.init.cmd |= cmd;
  frame.init.bcnth = (uint8_t)((len >> 8) & 0xFF);
  frame.init.bcntl = (uint8_t)(len & 0xFF);

  copied = MIN(len, ISIZE);
  if (!data) return;
  memcpy(frame.init.data, data, copied);
  CTAPHID_SendFrame();
  off += copied;

  while (len > off) {
    memset(&frame.cont, 0, sizeof(frame.cont));
    frame.cont.seq = (uint8_t)seq++;
    copied = MIN(len - off, CSIZE);
    memcpy(frame.cont.data, data + off, copied);
    CTAPHID_SendFrame();
    off += copied;
  }
}

static void CTAPHID_SendErrorResponse(uint32_t cid, uint8_t code) {
  DBG_MSG("error code 0x%x\n", (int)code);
  memset(&frame, 0, sizeof(frame));
  frame.cid = cid;
  frame.init.cmd = CTAPHID_ERROR;
  frame.init.bcnth = 0;
  frame.init.bcntl = 1;
  frame.init.data[0] = code;
  CTAPHID_SendFrame();
}

static void CTAPHID_Execute_Init(void) {
  CTAPHID_INIT_RESP *resp = (CTAPHID_INIT_RESP *)channel.data;
  uint32_t resp_cid;
  if (channel.cid == CID_BROADCAST)
    random_buffer((uint8_t *)&resp_cid, 4);
  else
    resp_cid = channel.cid;
  resp->cid = resp_cid;
  resp->versionInterface = CTAPHID_IF_VERSION; // Interface version
  resp->versionMajor = 1;                      // Major version number
  resp->versionMinor = 0;                      // Minor version number
  resp->versionBuild = 0;                      // Build version number
  resp->capFlags = CAPABILITY_CBOR;            // Capabilities flags
  CTAPHID_SendResponse(channel.cid, channel.cmd, (uint8_t *)resp, sizeof(CTAPHID_INIT_RESP));
}

static void CTAPHID_Execute_Msg(void) {
  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;
  CLA = channel.data[0];
  INS = channel.data[1];
  P1 = channel.data[2];
  P2 = channel.data[3];
  LC = (channel.data[5] << 8) | channel.data[6];
  DATA = &channel.data[7];
  LE = 0x10000;
  RDATA = channel.data;
  DBG_MSG("C: ");
  PRINT_HEX(channel.data, channel.bcnt_total);
  ctap_process_apdu_with_src(capdu, rapdu, CTAP_SRC_HID);
  channel.data[LL] = HI(SW);
  channel.data[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(RDATA, LL + 2);
  CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, LL + 2);
}

static void CTAPHID_Execute_Cbor(void) {
  DBG_MSG("C: ");
  PRINT_HEX(channel.data, channel.bcnt_total);
  size_t len = sizeof(channel.data);
  ctap_process_cbor_with_src(channel.data, channel.bcnt_total, channel.data, &len, CTAP_SRC_HID);
  DBG_MSG("R: ");
  PRINT_HEX(channel.data, len);
  CTAPHID_SendResponse(channel.cid, CTAPHID_CBOR, channel.data, len);
}

uint8_t CTAPHID_Loop(uint8_t wait_for_user) {
  uint8_t ret = LOOP_SUCCESS;
  if (channel.state == CTAPHID_BUSY && device_get_tick() > channel.expire) {
    DBG_MSG("CTAP Timeout\n");
    channel.state = CTAPHID_IDLE;
    CTAPHID_SendErrorResponse(channel.cid, ERR_MSG_TIMEOUT);
  }

  if (!has_frame) return LOOP_SUCCESS;

  if (frame.cid == 0 || (frame.cid == CID_BROADCAST && frame.init.cmd != CTAPHID_INIT)) {
    CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_CID);
    goto consume_frame;
  }
  if (channel.state == CTAPHID_BUSY && frame.cid != channel.cid) {
    CTAPHID_SendErrorResponse(frame.cid, ERR_CHANNEL_BUSY);
    goto consume_frame;
  }

  channel.cid = frame.cid;
  
  if (FRAME_TYPE(frame) == TYPE_INIT) {
    // DBG_MSG("CTAP init frame, cmd=0x%x\n", (int)frame.init.cmd);
    if (!wait_for_user && channel.state == CTAPHID_BUSY && frame.init.cmd != CTAPHID_INIT) { // self abort is ok
      DBG_MSG("wait_for_user=%d, cmd=0x%x\n", (int)wait_for_user, (int)frame.init.cmd);
      channel.state = CTAPHID_IDLE;
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
      goto consume_frame;
    }
    channel.bcnt_total = (uint16_t)MSG_LEN(frame);
    if (channel.bcnt_total > MAX_CTAP_BUFSIZE) {
      DBG_MSG("bcnt_total=%hu exceeds MAX_CTAP_BUFSIZE\n", channel.bcnt_total);
      CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_LEN);
      goto consume_frame;
    }
    uint16_t copied;
    channel.bcnt_current = copied = MIN(channel.bcnt_total, ISIZE);
    channel.state = CTAPHID_BUSY;
    channel.cmd = frame.init.cmd;
    channel.seq = 0;
    memcpy(channel.data, frame.init.data, copied);
    channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
  } else {
    // DBG_MSG("CTAP cont frame, state=%d cmd=0x%x seq=%d\n", (int)channel.state, (int)channel.cmd, (int)FRAME_SEQ(frame));
    if (channel.state == CTAPHID_IDLE) goto consume_frame; // ignore spurious continuation packet
    if (FRAME_SEQ(frame) != channel.seq++) {
      DBG_MSG("seq=%d\n", (int)FRAME_SEQ(frame));
      channel.state = CTAPHID_IDLE;
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
      goto consume_frame;
    }
    uint16_t copied;
    copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
    memcpy(channel.data + channel.bcnt_current, frame.cont.data, copied);
    channel.bcnt_current += copied;
  }
  has_frame = 0;

  if (channel.bcnt_current == channel.bcnt_total) {
    channel.expire = UINT32_MAX;
    switch (channel.cmd) {
    case CTAPHID_MSG:
      DBG_MSG("MSG\n");
      if (wait_for_user)
        CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
      else if (channel.bcnt_total < 4) // APDU CLA...P2
        CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
      else
        CTAPHID_Execute_Msg();
      break;
    case CTAPHID_CBOR:
      DBG_MSG("CBOR\n");
      if (wait_for_user)
        CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
      else if (channel.bcnt_total == 0)
        CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
      else
        CTAPHID_Execute_Cbor();
      break;
    case CTAPHID_INIT:
      DBG_MSG("INIT\n");
      if (wait_for_user)
        CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
      else
        CTAPHID_Execute_Init();
      break;
    case CTAPHID_PING:
      DBG_MSG("PING\n");
      if (wait_for_user)
        CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
      else
        CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, channel.bcnt_total);
      break;
     case CTAPHID_WINK:
      DBG_MSG("WINK\n");
      if (!wait_for_user) ctap_wink();
      CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, 0);
      break;
    case CTAPHID_CANCEL:
      DBG_MSG("CANCEL when wait_for_user=%d\n", (int)wait_for_user);
      ret = LOOP_CANCEL;
      break;
    default:
      DBG_MSG("Invalid CMD 0x%x\n", (int)channel.cmd);
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_CMD);
      break;
    }
    channel.state = CTAPHID_IDLE;
  }

consume_frame:
  has_frame = 0;
  return ret;
}

void CTAPHID_SendKeepAlive(uint8_t status) {
  memset(&frame, 0, sizeof(frame));
  frame.cid = channel.cid;
  frame.type = TYPE_INIT;
  frame.init.cmd |= CTAPHID_KEEPALIVE;
  frame.init.bcnth = 0;
  frame.init.bcntl = 1;
  frame.init.data[0] = status;
  CTAPHID_SendFrame();
}
