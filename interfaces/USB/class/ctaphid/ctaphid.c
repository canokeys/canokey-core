#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <rand.h>
#include <usbd_ctaphid.h>

extern USBD_HandleTypeDef usb_device;
static CTAPHID_FRAME frame;
static CTAPHID_Channel channel;
static volatile uint8_t has_frame;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

const uint16_t ISIZE = sizeof(frame.init.data);
const uint16_t CSIZE = sizeof(frame.cont.data);

uint8_t CTAPHID_Init(void) {
  channel.state = CTAPHID_IDLE;
  has_frame = 0;
  return 0;
}

uint8_t CTAPHID_OutEvent(uint8_t *data) {
  memcpy(&frame, data, sizeof(frame));
  has_frame = 1;
  return 0;
}

static void CTAPHID_SendFrame(void) { USBD_CTAPHID_SendReport(&usb_device, (uint8_t *)&frame, sizeof(CTAPHID_FRAME)); }

static void CTAPHID_SendErrorResponse(uint32_t cid, uint8_t code) {
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
  resp->capFlags = CAPFLAG_WINK;               // Capabilities flags
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
  PRINT_HEX(channel.data, channel.bcnt_total);
  ctap_process_apdu(capdu, rapdu);
  channel.data[LL] = HI(SW);
  channel.data[LL + 1] = LO(SW);
  PRINT_HEX(RDATA, LL + 2);
  CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, LL + 2);
}

static void CTAPHID_Execute_Ping(void) {
  CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, channel.bcnt_total);
}

void CTAPHID_Loop(void) {
  if (channel.state == CTAPHID_BUSY && device_get_tick() > channel.expire) {
    channel.state = CTAPHID_IDLE;
    return CTAPHID_SendErrorResponse(channel.cid, ERR_MSG_TIMEOUT);
  }

  if (!has_frame) return;
  has_frame = 0;

  if (frame.cid == 0 || (frame.cid == CID_BROADCAST && frame.init.cmd != CTAPHID_INIT))
    return CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_CID);
  if (channel.state == CTAPHID_BUSY && frame.cid != channel.cid)
    return CTAPHID_SendErrorResponse(frame.cid, ERR_CHANNEL_BUSY);

  channel.cid = frame.cid;

  if (FRAME_TYPE(frame) == TYPE_INIT) {
    if (channel.state == CTAPHID_BUSY && frame.init.cmd != CTAPHID_INIT) { // self abort is ok
      channel.state = CTAPHID_IDLE;
      return CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
    }
    channel.bcnt_total = (uint16_t)MSG_LEN(frame);
    if (channel.bcnt_total > MAX_CTAP_BUFSIZE) return CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_LEN);
    uint16_t copied;
    channel.bcnt_current = copied = MIN(channel.bcnt_total, ISIZE);
    channel.state = CTAPHID_BUSY;
    channel.cmd = frame.init.cmd;
    channel.seq = 0;
    memcpy(channel.data, frame.init.data, copied);
    channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
  } else if (FRAME_TYPE(frame) == TYPE_CONT) {
    if (channel.state == CTAPHID_IDLE) return; // ignore spurious continuation packet
    if (FRAME_SEQ(frame) != channel.seq++) {
      channel.state = CTAPHID_IDLE;
      return CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
    }
    uint16_t copied;
    copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
    memcpy(channel.data + channel.bcnt_current, frame.cont.data, copied);
    channel.bcnt_current += copied;
  }

  if (channel.bcnt_current == channel.bcnt_total) {
    switch (channel.cmd) {
    case CTAPHID_INIT:
      CTAPHID_Execute_Init();
      break;
    case CTAPHID_MSG:
      CTAPHID_Execute_Msg();
      break;
    case CTAPHID_PING:
      CTAPHID_Execute_Ping();
      break;
    default:
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_CMD);
      break;
    }
    channel.state = CTAPHID_IDLE;
  }
}

void CTAPHID_SendResponse(uint32_t cid, uint8_t cmd, uint8_t *data, uint16_t len) {
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
