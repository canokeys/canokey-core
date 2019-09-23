
#include <time.h>
#include "ctap-hid.h"
#include "ctap.h"
#include "apdu-adapter.h"

void FIDO_U2F_SendResponse(int ch, uint8_t cmd, uint16_t length, uint8_t *data);
void FIDO_U2F_SendError(int ch, uint8_t errorCode);
void FIDO_U2F_HandleCommand(int ch, uint8_t cmd, uint16_t length, uint8_t *data);
int NewChannel(uint32_t cid);
int FindChannelByCID(uint32_t cid, bool init);
void ClearChannel(int index);

typedef struct chan_ctx_t {
    uint8_t expectedCmdSeq, cmdReceived;
    uint8_t *cmdBuffer;
    uint16_t cmdBufferSize, cmdLength;
    uint32_t cmdCID;
    uint32_t lastRecvTick;

    uint8_t *respBuffer;
    uint8_t *respData;
    uint8_t nextRespSeq, respCmd;
    uint16_t respRemain;
} chan_ctx;


static uint32_t busyCID;
static uint32_t cidGen;
static chan_ctx chan[U2F_HID_CHANNELS+1]; // channel 0 reserved for broadcast

static uint64_t current_tick_ms()
{
    long            ms; // Milliseconds
    uint64_t          s;  // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_MONOTONIC, &spec);

    s  = spec.tv_sec;
    ms = spec.tv_nsec / 1000000; // Convert nanoseconds to milliseconds

    return s * 1000 + ms;
}

int8_t CTAP_HID_INIT(void)
{
    cidGen = 0x10000000;
    busyCID = 0;
    for (int i = 0; i < U2F_HID_CHANNELS+1; i++) {
        chan[i].expectedCmdSeq = 0xFF;
        chan[i].cmdCID = 0;
        chan[i].cmdBufferSize = 0;
        chan[i].respCmd = 0;
    }

    return (0);
}

int8_t CTAP_HID_OutEvent(uint8_t *Report_buf)
{
    struct FIDO_U2F_Message_t *initMsg = (struct FIDO_U2F_Message_t*)Report_buf;
    int iChan;
    if(initMsg->cmd & 0x80) {
        DBG_MSG("1st pkt of %#x is %#x", initMsg->cid, initMsg->cmd);
        iChan = FindChannelByCID(initMsg->cid, true);
        if(iChan < 0) {
            ERR_MSG("No such channels");
            return 0;
        }
        bool pendingCmd = chan[iChan].cmdReceived != 0;
        ClearChannel(iChan); // free channel before handling new command
        if(pendingCmd && initMsg->cmd != FIDO_U2F_HID_INIT) {
            FIDO_U2F_SendError(iChan, FIDO_U2F_ERR_INVALID_SEQ);
            return 0;
        }
        chan[iChan].cmdCID = initMsg->cid;
        if(initMsg->cid == 0) {
            //Channel ID 0 is reserved, reply with an error
            FIDO_U2F_SendError(0, FIDO_U2F_ERR_INVALID_CID);
            return 0;
        }
        if(busyCID && initMsg->cid != busyCID && initMsg->cmd != FIDO_U2F_HID_INIT) {
            FIDO_U2F_SendError(iChan, FIDO_U2F_ERR_CHANNEL_BUSY);
            return 0;
        }
        chan[iChan].cmdLength = ((uint16_t)initMsg->bcnth << 8) | initMsg->bcntl;
        if(chan[iChan].cmdLength > MAX_PAYLOAD_LEN) {
            FIDO_U2F_SendError(iChan, FIDO_U2F_ERR_INVALID_LEN);
            return 0;
        }
        DBG_MSG("allocating %hu bytes", chan[iChan].cmdLength);
        chan[iChan].cmdBuffer = malloc(chan[iChan].cmdLength);
        if(!chan[iChan].cmdBuffer) {
            ERR_MSG("No memory");
            FIDO_U2F_SendError(iChan, FIDO_U2F_ERR_OTHER);
            return 0;
        }
        chan[iChan].expectedCmdSeq = 0;
        chan[iChan].cmdBufferSize = sizeof(initMsg->data);
        chan[iChan].cmdReceived = initMsg->cmd;
        chan[iChan].lastRecvTick = current_tick_ms();
        DBG_MSG("Active %d", iChan);
        memcpy(chan[iChan].cmdBuffer, initMsg->data, MIN(chan[iChan].cmdLength, sizeof(initMsg->data)));
        if(initMsg->cmd != FIDO_U2F_HID_INIT)
            busyCID = initMsg->cid;
    } else {
        struct FIDO_U2F_Cont_Message_t *contMsg = (struct FIDO_U2F_Cont_Message_t*)Report_buf;
        DBG_MSG("seq %d", contMsg->seq);
        iChan = FindChannelByCID(contMsg->cid, false);
        if(iChan < 0 || !chan[iChan].cmdReceived) {
            // silently ignore to pass tests
            return (0);
        }
        if(contMsg->seq != chan[iChan].expectedCmdSeq) {
            FIDO_U2F_SendError(iChan, FIDO_U2F_ERR_INVALID_SEQ);
            return (0);
        }
        uint16_t l = MIN(chan[iChan].cmdLength - chan[iChan].cmdBufferSize, sizeof(contMsg->data));
        if(l == 0) {
            ERR_MSG("Empty pkt");
            FIDO_U2F_SendError(iChan, FIDO_U2F_ERR_INVALID_LEN);
            return (0);
        }
        memcpy(
            chan[iChan].cmdBuffer + chan[iChan].cmdBufferSize,
            contMsg->data,
            l
        );
        chan[iChan].cmdBufferSize += l;
        chan[iChan].expectedCmdSeq++;
        chan[iChan].lastRecvTick = current_tick_ms();
    }
    if(chan[iChan].cmdBufferSize >= chan[iChan].cmdLength) {
        DBG_MSG("total len %d", chan[iChan].cmdLength);
        FIDO_U2F_HandleCommand(iChan, chan[iChan].cmdReceived, chan[iChan].cmdLength, chan[iChan].cmdBuffer);
    }
    return (0);
    /* USER CODE END 6 */
}

void CTAP_HID_CheckTimeout()
{
    uint32_t now = current_tick_ms();
    for (int i = 0; i < U2F_HID_CHANNELS+1; i++) {
        if(chan[i].cmdReceived && chan[i].cmdBufferSize < chan[i].cmdLength
                && now > chan[i].lastRecvTick && now - chan[i].lastRecvTick > 700) {
            ERR_MSG("%d", i);
            FIDO_U2F_SendError(i, FIDO_U2F_ERR_MSG_TIMEOUT);
        }
    }
}

int8_t CTAP_HID_InEvent(CTAP_HID_SendReport_t CTAP_HID_SendReport)
{
    for (int i = 0; i < U2F_HID_CHANNELS+1; i++) {
        if(chan[i].respCmd) {
            struct FIDO_U2F_Message_t initMsg;
            initMsg.cid = chan[i].cmdCID;
            initMsg.cmd = chan[i].respCmd;
            initMsg.bcnth = chan[i].respRemain >> 8;
            initMsg.bcntl = chan[i].respRemain & 0xff;
            uint32_t datLen = MIN(sizeof(initMsg.data), chan[i].respRemain);
            memcpy(initMsg.data, chan[i].respData, datLen);
            chan[i].respRemain -= datLen;
            chan[i].respData += datLen;
            chan[i].nextRespSeq = 0;
            DBG_MSG("%#x remain %d", chan[i].respCmd, chan[i].respRemain);
            CTAP_HID_SendReport((uint8_t*)&initMsg, sizeof(struct FIDO_U2F_Message_t));
            chan[i].respCmd = 0;
        } else if(chan[i].respRemain) {
            struct FIDO_U2F_Cont_Message_t contMsg;
            contMsg.cid = chan[i].cmdCID;
            contMsg.seq = chan[i].nextRespSeq++;
            uint32_t datLen = MIN(sizeof(contMsg.data), chan[i].respRemain);
            memcpy(contMsg.data, chan[i].respData, datLen);
            chan[i].respRemain -= datLen;
            chan[i].respData += datLen;
            DBG_MSG("seq %d remain %d", contMsg.seq, chan[i].respRemain);
            CTAP_HID_SendReport((uint8_t*)&contMsg, sizeof(struct FIDO_U2F_Cont_Message_t));
        } else {
            continue;
        }
        if(!chan[i].respRemain) {
            if(busyCID == chan[i].cmdCID)
                busyCID = 0;
            ClearChannel(i);
        }
    }
    return (0);
}

void FIDO_U2F_SendError(int ch, uint8_t errorCode)
{
    FIDO_U2F_SendResponse(ch, FIDO_U2F_HID_ERROR, 1, &errorCode);
}

void FIDO_U2F_SendResponse(int ch, uint8_t cmd, uint16_t length, uint8_t *data)
{
    chan[ch].respCmd = cmd;
    chan[ch].respRemain = length;
    chan[ch].respData = data;
    // CTAP_HID_InEvent();
}

void FIDO_U2F_HandleCmdInit(int ch, uint16_t length, uint8_t *data)
{
    if(length != 8)
        return FIDO_U2F_SendError(ch, FIDO_U2F_ERR_INVALID_LEN);
    uint32_t newCID = chan[ch].cmdCID;
    if(newCID == FIDO_U2FHID_BROADCAST_CID) {
        newCID = ++cidGen;
        if(NewChannel(newCID) < 0) {
            ERR_MSG("busy");
            FIDO_U2F_SendError(ch, FIDO_U2F_ERR_CHANNEL_BUSY);
            return;
        }
    }
    uint8_t * respBuffer = malloc(17);
    if(!respBuffer) {
        ERR_MSG("No space");
        FIDO_U2F_SendError(ch, FIDO_U2F_ERR_OTHER);
        return;
    }
    chan[ch].respBuffer = respBuffer;
    memcpy(respBuffer, data, 8); //8 byte nonce
    memcpy(respBuffer+8, &newCID, 4); //4 byte channel ID
    respBuffer[12] = FIDO_U2FHID_IF_VERSION; // U2FHID protocol version identifier
    respBuffer[13] = 1; // Major device version number
    respBuffer[14] = 0; // Minor device version number
    respBuffer[15] = 0; // Build device version number
    respBuffer[16] = 4; // Capabilities flags: CAPABILITY_CBOR
    FIDO_U2F_SendResponse(ch, FIDO_U2F_HID_INIT, 17, respBuffer);
}


void FIDO_U2F_HandleMsgXfer(int ch, uint16_t length, uint8_t *data)
{
    size_t rLen = MAX_PAYLOAD_LEN;
    // static uint8_t rBuf[MAX_PAYLOAD_LEN];
    uint8_t *rBuf = chan[ch].respBuffer = malloc(rLen);
    if(!rBuf) {
        ERR_MSG("No space");
        FIDO_U2F_SendError(ch, FIDO_U2F_ERR_OTHER);
        return;
    }
    select_u2f_from_hid();
    if(virt_card_apdu_transceive(data, length, rBuf, &rLen)) {
        FIDO_U2F_SendError(ch, FIDO_U2F_ERR_OTHER);
    } else {
        FIDO_U2F_SendResponse(ch, FIDO_U2F_HID_MSG, rLen, rBuf);
    }
}


void FIDO2_HandleMsgXfer(int ch, uint16_t length, uint8_t *data)
{
    size_t rLen = MAX_PAYLOAD_LEN;
    // static uint8_t rBuf[MAX_PAYLOAD_LEN];
    uint8_t *rBuf = chan[ch].respBuffer = malloc(rLen);
    if(!rBuf) {
        ERR_MSG("No space");
        FIDO_U2F_SendError(ch, FIDO_U2F_ERR_OTHER);
        return;
    }
    if(ctap_process(data, length, rBuf, &rLen)) {
        FIDO_U2F_SendError(ch, FIDO_U2F_ERR_OTHER);
    } else {
        FIDO_U2F_SendResponse(ch, FIDO_U2F_HID_CBOR, rLen, rBuf);
    }
}

void FIDO_U2F_HandleCommand(int ch, uint8_t cmd, uint16_t length, uint8_t *data)
{
    uint32_t cid = chan[ch].cmdCID;
    switch (cmd) {
    case FIDO_U2F_HID_INIT:
        FIDO_U2F_HandleCmdInit(ch, length, data);
        break;

    case FIDO_U2F_HID_MSG:
        if(cid == FIDO_U2FHID_BROADCAST_CID)
            FIDO_U2F_SendError(ch, FIDO_U2F_ERR_INVALID_CID);
        else
            FIDO_U2F_HandleMsgXfer(ch, length, data);
        break;

    case FIDO_U2F_HID_CBOR:
        if(cid == FIDO_U2FHID_BROADCAST_CID)
            FIDO_U2F_SendError(ch, FIDO_U2F_ERR_INVALID_CID);
        else
            FIDO2_HandleMsgXfer(ch, length, data);
        break;

    case FIDO_U2F_HID_PING:
        if(cid == FIDO_U2FHID_BROADCAST_CID)
            FIDO_U2F_SendError(ch, FIDO_U2F_ERR_INVALID_CID);
        else
            FIDO_U2F_SendResponse(ch, cmd, length, data);
        break;

    default:
        FIDO_U2F_SendError(ch, FIDO_U2F_ERR_INVALID_CMD);
        break;
    }
}

int NewChannel(uint32_t cid)
{
    for (int i = 1; i <= U2F_HID_CHANNELS; i++) {
        if(chan[i].cmdCID == 0) {
            chan[i].cmdCID = cid;
            return i;
        }
    }
    uint32_t now = current_tick_ms();
    for (int i = 1; i <= U2F_HID_CHANNELS; i++) {
        if(chan[i].lastRecvTick < now && now - chan[i].lastRecvTick > 5000) {
            DBG_MSG("Recycling %d", i);
            chan[i].cmdCID = 0;
            ClearChannel(i);
            return i;
        }
    }
    return -1;
}

int FindChannelByCID(uint32_t cid, bool init)
{
    if(cid == FIDO_U2FHID_BROADCAST_CID || cid == 0) {
        return 0;
    }
    for (int i = 1; i <= U2F_HID_CHANNELS; i++) {
        if(chan[i].cmdCID == cid)
            return i;
    }
    return init ? NewChannel(cid) : -1;
}

void ClearChannel(int index)
{
    DBG_MSG("%d", index);
    chan[index].expectedCmdSeq = 0xFF;
    chan[index].respCmd = 0;
    chan[index].respRemain = 0;
    chan[index].cmdReceived = 0;
    if(chan[index].cmdBuffer) {
        free(chan[index].cmdBuffer);
        chan[index].cmdBuffer = 0;
    }
    if(chan[index].respBuffer) {
        free(chan[index].respBuffer);
        chan[index].respBuffer = 0;
    }
}
