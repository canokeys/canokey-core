#include <tusb.h>

#include <apdu.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <rand.h>
#include <usb_descriptors.h>

static CTAPHID_FRAME frame;
static CTAPHID_Channel channel;
static volatile uint8_t has_frame;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static CTAPHID_StateTypeDef hid_state;

const uint16_t ISIZE = sizeof(frame.init.data);
const uint16_t CSIZE = sizeof(frame.cont.data);

//==============================================================================
// CTAPHID functions
//==============================================================================
static void CTAPHID_SendFrame(void) {
  if (!tud_mounted()) return;

  int retry = 0;
  while (hid_state != CTAPHID_IDLE) {
    if (++retry > 50) {
      ERR_MSG("Wait HID ready timeout\n");
      return;
    }

    device_delay(1);
  }

  hid_state = CTAPHID_BUSY;
  // Report ID is always 0
  tud_hid_n_report(HID_ITF_CTAP, 0, &frame, sizeof(frame));
}

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
  ctap_process_apdu(capdu, rapdu);
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
  ctap_process_cbor(channel.data, channel.bcnt_total, channel.data, &len);
  DBG_MSG("R: ");
  PRINT_HEX(channel.data, len);
  CTAPHID_SendResponse(channel.cid, CTAPHID_CBOR, channel.data, len);
}

//==============================================================================
// Class init and loop
//==============================================================================
void ctap_hid_init() {
  channel.state = CTAPHID_IDLE;
  hid_state = CTAPHID_IDLE;
  has_frame = 0;
}

uint8_t ctap_hid_loop(uint8_t wait_for_user) {
  if (channel.state == CTAPHID_BUSY && device_get_tick() > channel.expire) {
    DBG_MSG("CTAP Timeout");
    channel.state = CTAPHID_IDLE;
    CTAPHID_SendErrorResponse(channel.cid, ERR_MSG_TIMEOUT);
    return LOOP_SUCCESS;
  }

  if (!has_frame) return LOOP_SUCCESS;
  has_frame = 0;

  if (frame.cid == 0 || (frame.cid == CID_BROADCAST && frame.init.cmd != CTAPHID_INIT)) {
    CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_CID);
    return LOOP_SUCCESS;
  }
  if (channel.state == CTAPHID_BUSY && frame.cid != channel.cid) {
    CTAPHID_SendErrorResponse(frame.cid, ERR_CHANNEL_BUSY);
    return LOOP_SUCCESS;
  }

  channel.cid = frame.cid;

  if (FRAME_TYPE(frame) == TYPE_INIT) {
    // DBG_MSG("CTAP init frame, cmd=0x%x\n", (int)frame.init.cmd);
    if (!wait_for_user && channel.state == CTAPHID_BUSY && frame.init.cmd != CTAPHID_INIT) { // self abort is ok
      channel.state = CTAPHID_IDLE;
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
      return LOOP_SUCCESS;
    }
    channel.bcnt_total = (uint16_t)MSG_LEN(frame);
    if (channel.bcnt_total > MAX_CTAP_BUFSIZE) {
      CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_LEN);
      return LOOP_SUCCESS;
    }
    uint16_t copied;
    channel.bcnt_current = copied = MIN(channel.bcnt_total, ISIZE);
    channel.state = CTAPHID_BUSY;
    channel.cmd = frame.init.cmd;
    channel.seq = 0;
    memcpy(channel.data, frame.init.data, copied);
    channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
  } else if (FRAME_TYPE(frame) == TYPE_CONT) {
    // DBG_MSG("CTAP cont frame, state=%d cmd=0x%x seq=%d\n", (int)channel.state, (int)channel.cmd,
    // (int)FRAME_SEQ(frame));
    if (channel.state == CTAPHID_IDLE) return LOOP_SUCCESS; // ignore spurious continuation packet
    if (FRAME_SEQ(frame) != channel.seq++) {
      channel.state = CTAPHID_IDLE;
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
      return LOOP_SUCCESS;
    }
    uint16_t copied;
    copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
    memcpy(channel.data + channel.bcnt_current, frame.cont.data, copied);
    channel.bcnt_current += copied;
  }

  uint8_t ret = LOOP_SUCCESS;
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
    case CTAPHID_CANCEL:
      DBG_MSG("CANCEL\n");
      ret = LOOP_CANCEL;
      break;
    default:
      DBG_MSG("Invalid CMD\n");
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_CMD);
      break;
    }
    channel.state = CTAPHID_IDLE;
  }

  return ret;
}

//==============================================================================
// TinyUSB stack callbacks
//==============================================================================
void ctap_hid_report_complete_cb(uint8_t const *report, uint8_t len) { hid_state = CTAPHID_IDLE; }

uint16_t ctap_hid_get_report_cb(uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen) {
  return 0;
}

void ctap_hid_set_report_cb(uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
  // report_id = 0 for OUTPUT data
  if (report_id != 0) return;

  // HID_REPORT_TYPE_INVALID means received generic OUTPUT data
  if (report_type != HID_REPORT_TYPE_INVALID) return;

  if (bufsize < sizeof(frame)) {
    ERR_MSG("CTAPHID: invalid frame size %d, need %d\n", bufsize, sizeof(frame));
    return;
  }

  memcpy(&frame, buffer, sizeof(frame));
  has_frame = 1;
}
