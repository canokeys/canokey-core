// SPDX-License-Identifier: Apache-2.0
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <rand.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>

#define CTAPHID_RX_QUEUE_SIZE 6

static CTAPHID_FRAME rx_frame;
static CTAPHID_FRAME rx_queue[CTAPHID_RX_QUEUE_SIZE];
static CTAPHID_FRAME tx_frame;
static CTAPHID_Channel channel;
static volatile uint8_t rx_head;
static volatile uint8_t rx_tail;
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
static size_t tx_pke_source_offset;

static const uint16_t ISIZE = sizeof(tx_frame.init.data);
static const uint16_t CSIZE = sizeof(tx_frame.cont.data);

static void CTAPHID_MarkCancelPending(uint32_t cid) {
  if (channel.executing && channel.cid == cid) channel.cancel_pending = 1;
}

static int CTAPHID_PKESourceRead(void *ctx, uint8_t *out, size_t max_len, size_t *written);
static void CTAPHID_SendErrorResponse(uint32_t cid, uint8_t code);
static void CTAPHID_Execute_Init(void);
static void CTAPHID_Execute_Msg(void);
static void CTAPHID_Execute_Cbor(void);

static void CTAPHID_ResetRxStorage(void) {
  if (channel.use_pke_buffer) {
    pke_buffer_clear();
    pke_buffer_release(PKE_BUFFER_OWNER_CTAP);
    channel.use_pke_buffer = 0;
  }
  channel.ready = 0;
}

static void CTAPHID_PKERequestSourceClose(void *ctx) {
  (void)ctx;
  CTAPHID_ResetRxStorage();
}

static int CTAPHID_AppendContinuation(const CTAPHID_FRAME *frame) {
  if (!frame || channel.state != CTAPHID_BUSY || FRAME_TYPE(*frame) != TYPE_CONT || frame->cid != channel.cid) return 0;
  if (FRAME_SEQ(*frame) != channel.seq) return 0;

  uint16_t copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
  channel.seq++;
  if (channel.use_pke_buffer) {
    if (copied != 0 && pke_buffer_write(channel.bcnt_current, frame->cont.data, copied) < 0) return -1;
  } else if (copied != 0) {
    memcpy(channel.data + channel.bcnt_current, frame->cont.data, copied);
  }
  channel.bcnt_current += copied;
  channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
  return 1;
}

static uint8_t CTAPHID_DispatchComplete(uint8_t wait_for_user) {
  if (wait_for_user && channel.cancel_pending) {
    channel.cancel_pending = 0;
    if (USBD_CTAPHID_WaitIdle() == USBD_OK) return LOOP_CANCEL;
  }
  if (channel.executing) return LOOP_SUCCESS;
  if (!channel.ready || channel.state != CTAPHID_BUSY || channel.bcnt_current != channel.bcnt_total)
    return LOOP_SUCCESS;

  uint8_t ret = LOOP_SUCCESS;
  channel.executing = 1;
  channel.expire = UINT32_MAX;
  switch (channel.cmd) {
  case CTAPHID_MSG:
    DBG_MSG("MSG\n");
    if (wait_for_user)
      CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
    else if (channel.bcnt_total < 4)
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
    else if (channel.use_pke_buffer) {
      tx_pke_source_offset = 0;
      CTAPHID_TxSource source = {
          .total_len = channel.bcnt_total,
          .read = CTAPHID_PKESourceRead,
          .close = CTAPHID_PKERequestSourceClose,
          .ctx = &tx_pke_source_offset,
      };
      if (CTAPHID_SendStreamSource(channel.cid, channel.cmd, &source) != 0)
        CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
    } else {
      CTAPHID_SendResponseAuto(channel.cid, channel.cmd, channel.data, channel.bcnt_total);
    }
    break;
  case CTAPHID_WINK:
    DBG_MSG("WINK\n");
    if (!wait_for_user) ctap_wink();
    CTAPHID_SendResponseAuto(channel.cid, channel.cmd, channel.data, 0);
    break;
  case CTAPHID_CANCEL:
    DBG_MSG("CANCEL when wait_for_user=%d\n", (int)wait_for_user);
    if (wait_for_user) USBD_CTAPHID_WaitIdle();
    ret = LOOP_CANCEL;
    break;
  default:
    DBG_MSG("Invalid CMD 0x%x\n", (int)channel.cmd);
    CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_CMD);
    break;
  }
  channel.executing = 0;
  if (!(channel.cmd == CTAPHID_PING && CTAPHID_TxBusy())) CTAPHID_ResetRxStorage();
  channel.state = CTAPHID_IDLE;
  return ret;
}

uint8_t CTAPHID_Init(uint8_t (*send_report)(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len)) {
  callback_send_report = send_report;
  channel.state = CTAPHID_IDLE;
  channel.ready = 0;
  channel.executing = 0;
  channel.cancel_pending = 0;
  rx_head = 0;
  rx_tail = 0;
  CTAPHID_TxReset();
  return 0;
}

uint8_t CTAPHID_OutEvent(uint8_t *data) {
  CTAPHID_FRAME frame;
  memcpy(&frame, data, sizeof(frame));
  if (CTAPHID_TxBusy()) {
    DBG_MSG("CTAPHID TX busy, dropping incoming report\n");
    return 0;
  }

  if (FRAME_TYPE(frame) == TYPE_INIT && frame.init.cmd == CTAPHID_CANCEL) {
    if (channel.executing && frame.cid == channel.cid && MSG_LEN(frame) == 0) {
      CTAPHID_MarkCancelPending(frame.cid);
      return 1;
    }
  }
  if (channel.ready) return 0;

  if (frame.cid == 0 || (frame.cid == CID_BROADCAST && frame.init.cmd != CTAPHID_INIT)) {
    CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_CID);
    return 1;
  }

  if (FRAME_TYPE(frame) == TYPE_INIT) {
    if (channel.state == CTAPHID_BUSY && frame.cid != channel.cid) return 0;

    if (!channel.executing && channel.state == CTAPHID_BUSY && frame.init.cmd != CTAPHID_INIT) {
      CTAPHID_ResetRxStorage();
      channel.state = CTAPHID_IDLE;
      return 0;
    }

    channel.cid = frame.cid;
    channel.bcnt_total = (uint16_t)MSG_LEN(frame);
    if (channel.bcnt_total > MAX_CTAP_BUFSIZE) return 0;

    uint16_t copied = MIN(channel.bcnt_total, ISIZE);
    CTAPHID_ResetRxStorage();
    channel.use_pke_buffer = 0;
    if (channel.bcnt_total > sizeof(channel.data)) {
      if (pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP) < 0) return 0;
      channel.use_pke_buffer = 1;
      if (pke_buffer_clear() < 0) {
        CTAPHID_ResetRxStorage();
        return 0;
      }
      if (copied != 0 && pke_buffer_write(0, frame.init.data, copied) < 0) {
        CTAPHID_ResetRxStorage();
        return 0;
      }
    } else if (copied != 0) {
      memcpy(channel.data, frame.init.data, copied);
    }
    channel.bcnt_current = copied;
    channel.state = CTAPHID_BUSY;
    channel.cmd = frame.init.cmd;
    channel.seq = 0;
    channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
    channel.ready = (channel.bcnt_current == channel.bcnt_total);
    return 1;
  }

  if (channel.state == CTAPHID_BUSY && frame.cid == channel.cid) {
    int fast = CTAPHID_AppendContinuation(&frame);
    if (fast > 0) {
      channel.ready = (channel.bcnt_current == channel.bcnt_total);
      return 1;
    }
    if (fast < 0) {
      CTAPHID_ResetRxStorage();
      channel.state = CTAPHID_IDLE;
      return 0;
    }
  }

  uint8_t next_head = (uint8_t)((rx_head + 1) % CTAPHID_RX_QUEUE_SIZE);
  if (next_head == rx_tail) {
    ERR_MSG("overrun\n");
    return 0;
  }
  memcpy(&rx_queue[rx_head], &frame, sizeof(rx_queue[rx_head]));
  rx_head = next_head;
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
  const uint8_t had_stream = tx_stream.active;
  if (tx_stream.active && tx_stream.source.close) tx_stream.source.close(tx_stream.source.ctx);
  memset(&tx_stream, 0, sizeof(tx_stream));
  memset(&tx_mem_source, 0, sizeof(tx_mem_source));
  tx_pke_source_offset = 0;
  if (had_stream) device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
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
  CTAPHID_ReleaseSharedBuffer();
}

int CTAPHID_AcquireSharedBuffer(uint8_t **buf, size_t *len) {
  if (acquire_apdu_buffer(BUFFER_OWNER_CTAPHID) != 0) return -1;
  if (buf) *buf = shared_io_buffer;
  if (len) *len = APDU_BUFFER_SIZE;
  return 0;
}

void CTAPHID_ReleaseSharedBuffer(void) { release_apdu_buffer(BUFFER_OWNER_CTAPHID); }

void CTAPHID_CloseSharedBufferSource(void *ctx) {
  (void)ctx;
  CTAPHID_ReleaseSharedBuffer();
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
  if (!source) {
    DBG_MSG("CTAPHID source stream missing source\n");
    return -1;
  }
  if (tx_stream.active) {
    DBG_MSG("CTAPHID source stream busy active=%u finishing=%u offset=%zu len=%zu\n", tx_stream.active,
            tx_stream.finishing, tx_stream.offset, tx_stream.len);
    if (!tx_stream.finishing) return -1;
    CTAPHID_TxReset();
  }
  if (source->total_len > UINT16_MAX) {
    DBG_MSG("CTAPHID source stream len exceeds u16: %zu\n", source->total_len);
    return -1;
  }
  if (source->total_len > (size_t)ISIZE + 128u * (size_t)CSIZE) {
    DBG_MSG("CTAPHID source stream len exceeds HID seq window: %zu\n", source->total_len);
    return -1;
  }
  if (source->total_len != 0 && source->read == NULL) {
    DBG_MSG("CTAPHID source stream missing reader len=%zu\n", source->total_len);
    return -1;
  }
  if (USBD_CTAPHID_WaitIdle() != USBD_OK) {
    DBG_MSG("CTAPHID source stream wait idle timeout len=%zu\n", source->total_len);
    return -1;
  }

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
    uint8_t *resp_buf = channel.data;
    size_t copied = 0;
    if (source->total_len != 0 &&
        (!source->read || source->read(source->ctx, resp_buf, source->total_len, &copied) != 0 ||
         copied != source->total_len)) {
      if (source->close) source->close(source->ctx);
      return -1;
    }
    CTAPHID_SendResponse(cid, cmd, resp_buf, (uint16_t)source->total_len);
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

static int CTAPHID_PKESourceRead(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  size_t *offset = (size_t *)ctx;
  size_t copied = MIN(tx_stream.len - tx_stream.offset, max_len);
  if (copied != 0 && pke_buffer_read(*offset, out, copied) < 0) return -1;
  *offset += copied;
  *written = copied;
  return 0;
}

static int CTAPHID_SendGlobalBufferResponseAuto(uint32_t cid, uint8_t cmd, size_t len) {
  if (len > UINT16_MAX) {
    CTAPHID_ReleaseSharedBuffer();
    return -1;
  }
  if (len <= CTAPHID_STREAM_THRESHOLD) {
    CTAPHID_SendResponse(cid, cmd, shared_io_buffer, (uint16_t)len);
    CTAPHID_ReleaseSharedBuffer();
    return 0;
  }

  tx_mem_source.data = shared_io_buffer;
  tx_mem_source.offset = 0;
  CTAPHID_TxSource source = {
      .total_len = len,
      .read = CTAPHID_MemSourceRead,
      .close = CTAPHID_GlobalBufferSourceClose,
      .ctx = &tx_mem_source,
  };
  if (CTAPHID_SendStreamSource(cid, cmd, &source) != 0) {
    CTAPHID_ReleaseSharedBuffer();
    return -1;
  }
  return 0;
}

static int CTAPHID_LoadRequestData(uint8_t *dst, size_t len) {
  if (!dst) return -1;
  if (len == 0) return 0;
  if (channel.use_pke_buffer) return pke_buffer_read(0, dst, len);
  memcpy(dst, channel.data, len);
  return 0;
}

static int CTAPHID_RequestRead(void *ctx, size_t offset, uint8_t *buf, size_t len) {
  UNUSED(ctx);
  if (offset > channel.bcnt_total || len > channel.bcnt_total - offset) return -1;
  if (channel.use_pke_buffer) return pke_buffer_read(offset, buf, len);
  memcpy(buf, channel.data + offset, len);
  return 0;
}

void CTAPHID_TxContinue(void) {
  if (!tx_stream.active) return;
  device_applet_session_touch(DEVICE_APPLET_SESSION_CTAPHID);
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
  if (channel.bcnt_total < 7) {
    CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
    return;
  }

  uint8_t req_head[7];
  if (CTAPHID_LoadRequestData(req_head, sizeof(req_head)) < 0) {
    CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
    return;
  }
  if (acquire_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID) != 0) {
    CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
    return;
  }
  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;
  CLA = req_head[0];
  INS = req_head[1];
  P1 = req_head[2];
  P2 = req_head[3];
  LC = ((uint16_t)req_head[5] << 8) | req_head[6];
  if (LC > channel.bcnt_total - 7) {
    release_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID);
    CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
    return;
  }
  size_t le_len = channel.bcnt_total - 7 - LC;
  if (le_len == 2) {
    uint8_t le[2];
    if (CTAPHID_RequestRead(NULL, 7 + LC, le, sizeof(le)) < 0) {
      release_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID);
      CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
      return;
    }
    LE = ((uint16_t)le[0] << 8) | le[1];
    if (LE == 0) LE = 0x10000;
  } else if (le_len == 0) {
    LE = 0x10000;
  } else {
    release_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID);
    CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
    return;
  }
  DATA = channel.use_pke_buffer ? req_head : channel.data + 7;
  RDATA = shared_io_buffer;
  DBG_MSG("C: ");
  if (!channel.use_pke_buffer) PRINT_HEX(channel.data, channel.bcnt_total);
  ctap_req_src_t req_src = {
      .read = CTAPHID_RequestRead,
      .ctx = NULL,
      .base_offset = 7,
      .len = LC,
  };
  ctap_process_apdu_source_with_src(capdu, &req_src, rapdu, CTAP_SRC_HID);
  shared_io_buffer[LL] = HI(SW);
  shared_io_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(RDATA, LL + 2);
  if (CTAPHID_SendGlobalBufferResponseAuto(channel.cid, channel.cmd, LL + 2) != 0) {
    device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
    CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
    return;
  }
  if (!CTAPHID_TxBusy()) device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
}

static void CTAPHID_Execute_Cbor(void) {
  if (device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID) != 0) {
    CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
    return;
  }
  device_applet_session_touch(DEVICE_APPLET_SESSION_CTAPHID);
  DBG_MSG("C: ");
  if (!channel.use_pke_buffer) PRINT_HEX(channel.data, channel.bcnt_total);
  CTAPHID_TxSource source;
  ctap_req_src_t req_src = {
      .read = CTAPHID_RequestRead,
      .ctx = NULL,
      .base_offset = 0,
      .len = channel.bcnt_total,
  };
  int stream_ret =
      ctap_process_cbor_stream_source_with_src(&req_src, channel.data, sizeof(channel.data), &source, CTAP_SRC_HID);
  if (stream_ret > 0) {
    DBG_MSG("R: response len=%zu\n", source.total_len);
    if (CTAPHID_SendSourceResponseAuto(channel.cid, CTAPHID_CBOR, &source) != 0) {
      device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
      CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
      return;
    }
    if (!CTAPHID_TxBusy()) device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
    return;
  }
  if (stream_ret < 0) {
    device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
    CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
    return;
  }
  device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
  CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
}

uint8_t CTAPHID_Loop(uint8_t wait_for_user) {
  uint8_t ret = LOOP_SUCCESS;
  USBD_CTAPHID_ServiceReceive();
  if (channel.state == CTAPHID_BUSY && device_get_tick() > channel.expire) {
    DBG_MSG("CTAP Timeout\n");
    CTAPHID_ResetRxStorage();
    channel.state = CTAPHID_IDLE;
    CTAPHID_SendErrorResponse(channel.cid, ERR_MSG_TIMEOUT);
  }

  ret = CTAPHID_DispatchComplete(wait_for_user);
  if (ret != LOOP_SUCCESS) return ret;

  while (!channel.ready && rx_head != rx_tail) {
    memcpy(&rx_frame, &rx_queue[rx_tail], sizeof(rx_frame));
    rx_tail = (uint8_t)((rx_tail + 1) % CTAPHID_RX_QUEUE_SIZE);

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
      if (rx_frame.init.cmd == CTAPHID_CANCEL && channel.executing && rx_frame.cid == channel.cid &&
          MSG_LEN(rx_frame) == 0) {
        CTAPHID_MarkCancelPending(rx_frame.cid);
        goto consume_frame;
      }
      // DBG_MSG("CTAP init frame, cmd=0x%x\n", (int)frame.init.cmd);
      if (!wait_for_user && channel.state == CTAPHID_BUSY && rx_frame.init.cmd != CTAPHID_INIT) { // self abort is ok
        DBG_MSG("wait_for_user=%d, cmd=0x%x\n", (int)wait_for_user, (int)rx_frame.init.cmd);
        CTAPHID_ResetRxStorage();
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
      CTAPHID_ResetRxStorage();
      channel.use_pke_buffer = 0;
      if (channel.bcnt_total > sizeof(channel.data)) {
        if (pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP) < 0) {
          CTAPHID_SendErrorResponse(rx_frame.cid, ERR_CHANNEL_BUSY);
          goto consume_frame;
        }
        channel.use_pke_buffer = 1;
        if (pke_buffer_clear() < 0) {
          CTAPHID_ResetRxStorage();
          CTAPHID_SendErrorResponse(rx_frame.cid, ERR_OTHER);
          goto consume_frame;
        }
        if (copied != 0 && pke_buffer_write(0, rx_frame.init.data, copied) < 0) {
          CTAPHID_ResetRxStorage();
          CTAPHID_SendErrorResponse(rx_frame.cid, ERR_OTHER);
          goto consume_frame;
        }
      } else if (copied != 0) {
        memcpy(channel.data, rx_frame.init.data, copied);
      }
      channel.state = CTAPHID_BUSY;
      channel.cmd = rx_frame.init.cmd;
      channel.seq = 0;
      channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
      channel.ready = (channel.bcnt_current == channel.bcnt_total);
    } else {
      // DBG_MSG("CTAP cont frame, state=%d cmd=0x%x seq=%d\n", (int)channel.state, (int)channel.cmd,
      // (int)FRAME_SEQ(frame));
      if (channel.state == CTAPHID_IDLE) goto consume_frame; // ignore spurious continuation packet
      if (FRAME_SEQ(rx_frame) != channel.seq++) {
        DBG_MSG("seq=%d\n", (int)FRAME_SEQ(rx_frame));
        CTAPHID_ResetRxStorage();
        channel.state = CTAPHID_IDLE;
        CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
        goto consume_frame;
      }
      uint16_t copied;
      copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
      if (channel.use_pke_buffer) {
        if (copied != 0 && pke_buffer_write(channel.bcnt_current, rx_frame.cont.data, copied) < 0) {
          CTAPHID_ResetRxStorage();
          channel.state = CTAPHID_IDLE;
          CTAPHID_SendErrorResponse(channel.cid, ERR_OTHER);
          goto consume_frame;
        }
      } else if (copied != 0) {
        memcpy(channel.data + channel.bcnt_current, rx_frame.cont.data, copied);
      }
      channel.bcnt_current += copied;
      channel.ready = (channel.bcnt_current == channel.bcnt_total);
    }
    ret = CTAPHID_DispatchComplete(wait_for_user);

  consume_frame:
    USBD_CTAPHID_ServiceReceive();
    if (ret != LOOP_SUCCESS) break;
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
