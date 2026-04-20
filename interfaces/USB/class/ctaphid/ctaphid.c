// SPDX-License-Identifier: Apache-2.0
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <rand.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>

static CTAPHID_FRAME rx_frame;
static CTAPHID_FRAME tx_frame;
static CTAPHID_Channel channel;
static volatile uint8_t has_frame;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static uint8_t (*callback_send_report)(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len);

typedef struct {
  uint8_t active;
  uint8_t finishing;
  uint8_t first;
  uint8_t seq;
  uint32_t cid;
  uint8_t cmd;
  size_t len;
  size_t offset;
  CTAPHID_TxSource source;
} CTAPHID_TxStream;

static CTAPHID_TxStream tx_stream;

typedef struct {
  const uint8_t *data;
  size_t offset;
} CTAPHID_MemSource;

static CTAPHID_MemSource tx_mem_source;

const uint16_t ISIZE = sizeof(tx_frame.init.data);
const uint16_t CSIZE = sizeof(tx_frame.cont.data);

uint8_t CTAPHID_Init(uint8_t (*send_report)(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len)) {
  callback_send_report = send_report;
  channel.state = CTAPHID_IDLE;
  has_frame = 0;
  CTAPHID_TxReset();
  return 0;
}

uint8_t CTAPHID_OutEvent(uint8_t *data) {
  if (CTAPHID_TxBusy()) {
    DBG_MSG("CTAPHID TX busy, dropping incoming report\n");
    return 0;
  }
  if (has_frame) {
    ERR_MSG("overrun\n");
    return 0;
  }
  memcpy(&rx_frame, data, sizeof(rx_frame));
  has_frame = 1;
  return 1;
}

static uint8_t CTAPHID_SendFrame(void) {
  if (!callback_send_report) return 1;
  return callback_send_report(&usb_device, (uint8_t *)&tx_frame, sizeof(CTAPHID_FRAME));
}

static void CTAPHID_SendResponse(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len) {
  uint16_t off = 0;
  size_t copied;
  uint8_t seq = 0;

  memset(&tx_frame, 0, sizeof(tx_frame));
  tx_frame.cid = cid;
  tx_frame.type = TYPE_INIT;
  tx_frame.init.cmd |= cmd;
  tx_frame.init.bcnth = (uint8_t)((len >> 8) & 0xFF);
  tx_frame.init.bcntl = (uint8_t)(len & 0xFF);

  copied = MIN(len, ISIZE);
  if (len != 0 && !data) return;
  if (copied != 0) memcpy(tx_frame.init.data, data, copied);
  CTAPHID_SendFrame();
  off += copied;

  while (len > off) {
    memset(&tx_frame.cont, 0, sizeof(tx_frame.cont));
    tx_frame.cont.seq = (uint8_t)seq++;
    copied = MIN(len - off, CSIZE);
    memcpy(tx_frame.cont.data, data + off, copied);
    CTAPHID_SendFrame();
    off += copied;
  }
}

uint8_t CTAPHID_TxBusy(void) { return tx_stream.active; }

void CTAPHID_TxReset(void) {
  if (tx_stream.active && tx_stream.source.close) tx_stream.source.close(tx_stream.source.ctx);
  memset(&tx_stream, 0, sizeof(tx_stream));
  memset(&tx_mem_source, 0, sizeof(tx_mem_source));
}

static int CTAPHID_MemSourceRead(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAPHID_MemSource *source = (CTAPHID_MemSource *)ctx;
  size_t copied = MIN(tx_stream.len - tx_stream.offset, max_len);
  if (copied != 0) memcpy(out, source->data + source->offset, copied);
  source->offset += copied;
  *written = copied;
  return 0;
}

static void CTAPHID_GlobalBufferSourceClose(void *ctx) {
  (void)ctx;
  release_apdu_buffer(BUFFER_OWNER_CTAPHID);
}

static int CTAPHID_TxFillFrame(void) {
  size_t remaining = tx_stream.len - tx_stream.offset;
  size_t copied;
  uint8_t *payload;
  size_t payload_size;

  memset(&tx_frame, 0, sizeof(tx_frame));
  tx_frame.cid = tx_stream.cid;

  if (tx_stream.first) {
    tx_frame.type = TYPE_INIT;
    tx_frame.init.cmd |= tx_stream.cmd;
    tx_frame.init.bcnth = (uint8_t)((tx_stream.len >> 8) & 0xFF);
    tx_frame.init.bcntl = (uint8_t)(tx_stream.len & 0xFF);
    payload = tx_frame.init.data;
    payload_size = ISIZE;
    tx_stream.first = 0;
  } else {
    tx_frame.cont.seq = tx_stream.seq++;
    payload = tx_frame.cont.data;
    payload_size = CSIZE;
  }

  copied = 0;
  if (remaining != 0) {
    const size_t want = MIN(remaining, payload_size);
    if (!tx_stream.source.read) return -1;
    if (tx_stream.source.read(tx_stream.source.ctx, payload, want, &copied) != 0) return -1;
    if (copied != want) return -1;
  }

  tx_stream.offset += copied;
  if (tx_stream.offset == tx_stream.len) tx_stream.finishing = 1;
  return 0;
}

static int CTAPHID_TxPump(void) {
  if (!tx_stream.active || tx_stream.finishing) return 0;
  if (CTAPHID_TxFillFrame() != 0) {
    CTAPHID_TxReset();
    return -1;
  }
  if (CTAPHID_SendFrame() != 0) {
    CTAPHID_TxReset();
    return -1;
  }
  return 0;
}

int CTAPHID_SendStreamSource(uint32_t cid, uint8_t cmd, const CTAPHID_TxSource *source) {
  if (!source) return -1;
  if (tx_stream.active) return -1;
  if (source->total_len > UINT16_MAX) return -1;
  if (source->total_len > (size_t)ISIZE + 128u * (size_t)CSIZE) return -1;
  if (source->total_len != 0 && source->read == NULL) return -1;

  tx_stream.active = 1;
  tx_stream.finishing = 0;
  tx_stream.first = 1;
  tx_stream.seq = 0;
  tx_stream.cid = cid;
  tx_stream.cmd = cmd;
  tx_stream.len = source->total_len;
  tx_stream.offset = 0;
  tx_stream.source = *source;

  DBG_MSG("CTAPHID source stream start len=%zu\n", source->total_len);
  return CTAPHID_TxPump();
}

int CTAPHID_SendStreamResponse(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len) {
  if (len != 0 && data == NULL) return -1;
  tx_mem_source.data = data;
  tx_mem_source.offset = 0;
  CTAPHID_TxSource source = {
      .total_len = len,
      .read = CTAPHID_MemSourceRead,
      .close = NULL,
      .ctx = &tx_mem_source,
  };
  return CTAPHID_SendStreamSource(cid, cmd, &source);
}

int CTAPHID_SendResponseAuto(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len) {
  if (len > UINT16_MAX) return -1;
  if (len <= CTAPHID_STREAM_THRESHOLD) {
    DBG_MSG("CTAPHID response len=%zu mode=inline\n", len);
    CTAPHID_SendResponse(cid, cmd, data, (uint16_t)len);
    return 0;
  }
  DBG_MSG("CTAPHID response len=%zu mode=stream\n", len);
  return CTAPHID_SendStreamResponse(cid, cmd, data, len);
}

static int CTAPHID_SendSourceResponseAuto(uint32_t cid, uint8_t cmd, CTAPHID_TxSource *source) {
  if (!source) return -1;
  if (source->total_len <= CTAPHID_STREAM_THRESHOLD) {
    DBG_MSG("CTAPHID source response len=%zu mode=inline\n", source->total_len);
    size_t copied = 0;
    if (source->total_len != 0 &&
        (!source->read || source->read(source->ctx, channel.data, source->total_len, &copied) != 0 ||
         copied != source->total_len)) {
      if (source->close) source->close(source->ctx);
      return -1;
    }
    CTAPHID_SendResponse(cid, cmd, channel.data, (uint16_t)source->total_len);
    if (source->close) source->close(source->ctx);
    return 0;
  }
  DBG_MSG("CTAPHID source response len=%zu mode=stream\n", source->total_len);
  if (CTAPHID_SendStreamSource(cid, cmd, source) != 0) {
    if (source->close) source->close(source->ctx);
    return -1;
  }
  return 0;
}

static int CTAPHID_SendGlobalBufferResponseAuto(uint32_t cid, uint8_t cmd, size_t len) {
  if (len > UINT16_MAX) {
    release_apdu_buffer(BUFFER_OWNER_CTAPHID);
    return -1;
  }
  if (len <= CTAPHID_STREAM_THRESHOLD) {
    CTAPHID_SendResponse(cid, cmd, global_buffer, (uint16_t)len);
    release_apdu_buffer(BUFFER_OWNER_CTAPHID);
    return 0;
  }

  tx_mem_source.data = global_buffer;
  tx_mem_source.offset = 0;
  CTAPHID_TxSource source = {
      .total_len = len,
      .read = CTAPHID_MemSourceRead,
      .close = CTAPHID_GlobalBufferSourceClose,
      .ctx = &tx_mem_source,
  };
  if (CTAPHID_SendStreamSource(cid, cmd, &source) != 0) {
    release_apdu_buffer(BUFFER_OWNER_CTAPHID);
    return -1;
  }
  return 0;
}

void CTAPHID_TxContinue(void) {
  if (!tx_stream.active) return;
  if (tx_stream.finishing) {
    DBG_MSG("CTAPHID stream done len=%zu\n", tx_stream.len);
    CTAPHID_TxReset();
    return;
  }
  CTAPHID_TxPump();
}

static void CTAPHID_SendErrorResponse(uint32_t cid, uint8_t code) {
  DBG_MSG("error code 0x%x\n", (int)code);
  memset(&tx_frame, 0, sizeof(tx_frame));
  tx_frame.cid = cid;
  tx_frame.init.cmd = CTAPHID_ERROR;
  tx_frame.init.bcnth = 0;
  tx_frame.init.bcntl = 1;
  tx_frame.init.data[0] = code;
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
  CTAPHID_SendResponseAuto(channel.cid, channel.cmd, (uint8_t *)resp, sizeof(CTAPHID_INIT_RESP));
}

static void CTAPHID_Execute_Msg(void) {
  if (acquire_apdu_buffer(BUFFER_OWNER_CTAPHID) != 0) {
    CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
    return;
  }
  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;
  CLA = channel.data[0];
  INS = channel.data[1];
  P1 = channel.data[2];
  P2 = channel.data[3];
  LC = (channel.data[5] << 8) | channel.data[6];
  DATA = &channel.data[7];
  LE = 0x10000;
  RDATA = global_buffer;
  DBG_MSG("C: ");
  PRINT_HEX(channel.data, channel.bcnt_total);
  ctap_process_apdu_with_src(capdu, rapdu, CTAP_SRC_HID);
  global_buffer[LL] = HI(SW);
  global_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(RDATA, LL + 2);
  if (CTAPHID_SendGlobalBufferResponseAuto(channel.cid, channel.cmd, LL + 2) != 0)
    CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
}

static void CTAPHID_Execute_Cbor(void) {
  DBG_MSG("C: ");
  PRINT_HEX(channel.data, channel.bcnt_total);
  CTAPHID_TxSource source;
  int stream_ret = ctap_process_cbor_stream_with_src(channel.data, channel.bcnt_total, channel.data,
                                                     sizeof(channel.data), &source, CTAP_SRC_HID);
  if (stream_ret > 0) {
    DBG_MSG("R: response len=%zu\n", source.total_len);
    if (CTAPHID_SendSourceResponseAuto(channel.cid, CTAPHID_CBOR, &source) != 0)
      CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
    return;
  }
  if (stream_ret < 0) {
    CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
    return;
  }
  CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
}

uint8_t CTAPHID_Loop(uint8_t wait_for_user) {
  uint8_t ret = LOOP_SUCCESS;
  if (channel.state == CTAPHID_BUSY && device_get_tick() > channel.expire) {
    DBG_MSG("CTAP Timeout\n");
    channel.state = CTAPHID_IDLE;
    CTAPHID_SendErrorResponse(channel.cid, ERR_MSG_TIMEOUT);
  }

  if (!has_frame) return LOOP_SUCCESS;

  if (CTAPHID_TxBusy()) {
    DBG_MSG("CTAPHID TX busy, dropping incoming frame\n");
    goto consume_frame;
  }

  if (rx_frame.cid == 0 || (rx_frame.cid == CID_BROADCAST && rx_frame.init.cmd != CTAPHID_INIT)) {
    CTAPHID_SendErrorResponse(rx_frame.cid, ERR_INVALID_CID);
    goto consume_frame;
  }
  if (channel.state == CTAPHID_BUSY && rx_frame.cid != channel.cid) {
    CTAPHID_SendErrorResponse(rx_frame.cid, ERR_CHANNEL_BUSY);
    goto consume_frame;
  }

  channel.cid = rx_frame.cid;

  if (FRAME_TYPE(rx_frame) == TYPE_INIT) {
    // DBG_MSG("CTAP init frame, cmd=0x%x\n", (int)frame.init.cmd);
    if (!wait_for_user && channel.state == CTAPHID_BUSY && rx_frame.init.cmd != CTAPHID_INIT) { // self abort is ok
      DBG_MSG("wait_for_user=%d, cmd=0x%x\n", (int)wait_for_user, (int)rx_frame.init.cmd);
      channel.state = CTAPHID_IDLE;
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
      goto consume_frame;
    }
    channel.bcnt_total = (uint16_t)MSG_LEN(rx_frame);
    if (channel.bcnt_total > MAX_CTAP_BUFSIZE) {
      DBG_MSG("bcnt_total=%hu exceeds MAX_CTAP_BUFSIZE\n", channel.bcnt_total);
      CTAPHID_SendErrorResponse(rx_frame.cid, ERR_INVALID_LEN);
      goto consume_frame;
    }
    uint16_t copied;
    channel.bcnt_current = copied = MIN(channel.bcnt_total, ISIZE);
    channel.state = CTAPHID_BUSY;
    channel.cmd = rx_frame.init.cmd;
    channel.seq = 0;
    memcpy(channel.data, rx_frame.init.data, copied);
    channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
  } else {
    // DBG_MSG("CTAP cont frame, state=%d cmd=0x%x seq=%d\n", (int)channel.state, (int)channel.cmd,
    // (int)FRAME_SEQ(frame));
    if (channel.state == CTAPHID_IDLE) goto consume_frame; // ignore spurious continuation packet
    if (FRAME_SEQ(rx_frame) != channel.seq++) {
      DBG_MSG("seq=%d\n", (int)FRAME_SEQ(rx_frame));
      channel.state = CTAPHID_IDLE;
      CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
      goto consume_frame;
    }
    uint16_t copied;
    copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
    memcpy(channel.data + channel.bcnt_current, rx_frame.cont.data, copied);
    channel.bcnt_current += copied;
  }
  has_frame = 0;
  USBD_CTAPHID_PrepareReceive();

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
        CTAPHID_SendResponseAuto(channel.cid, channel.cmd, channel.data, channel.bcnt_total);
      break;
    case CTAPHID_WINK:
      DBG_MSG("WINK\n");
      if (!wait_for_user) ctap_wink();
      CTAPHID_SendResponseAuto(channel.cid, channel.cmd, channel.data, 0);
      break;
    case CTAPHID_CANCEL:
      DBG_MSG("CANCEL when wait_for_user=%d\n", (int)wait_for_user);
      if (wait_for_user) {
        // A KEEPALIVE frame may still occupy the USB IN endpoint. Wait for
        // the host to read it so the subsequent error response (sent by the
        // caller after the call-chain unwinds) is not silently dropped by
        // USBD_CTAPHID_SendReport's 50 ms busy-wait timeout.
        USBD_CTAPHID_WaitIdle();
      }
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
  if (has_frame) {
    has_frame = 0;
    USBD_CTAPHID_PrepareReceive();
  }
  return ret;
}

void CTAPHID_SendKeepAlive(uint8_t status) {
  if (CTAPHID_TxBusy()) return;
  memset(&tx_frame, 0, sizeof(tx_frame));
  tx_frame.cid = channel.cid;
  tx_frame.type = TYPE_INIT;
  tx_frame.init.cmd |= CTAPHID_KEEPALIVE;
  tx_frame.init.bcnth = 0;
  tx_frame.init.bcntl = 1;
  tx_frame.init.data[0] = status;
  CTAPHID_SendFrame();
}
