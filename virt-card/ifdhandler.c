/*****************************************************************
/
/ File   :   ifdhandler.c
/ Author :   David Corcoran <corcoran@linuxnet.com>
/ Date   :   June 15, 2000
/ Purpose:   This provides reader specific low-level calls.
/            See http://www.linuxnet.com for more information.
/ License:   See file LICENSE
/
******************************************************************/

#include <ifdhandler.h>
#include <reader.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "apdu-adapter.h"
#include "fabrication.h"
#include "../openpgp/openpgp.h"

const static UCHAR ATR[] = {0x3B, 0xE9, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x4A, 0x43, 0x4F, 0x50, 0x32, 0x34, 0x32, 0x52, 0x32, 0xA0};
static int applet_init = 0;

RESPONSECODE IFDHCreateChannel ( DWORD Lun, DWORD Channel )
{
    printf("IFDHCreateChannel %ld %ld\n", Lun, Channel);
    if(!applet_init) {
        u2f_fabrication_procedure();
        openpgp_initialize();
        applet_init = 1;
    }
    return IFD_SUCCESS;
}

RESPONSECODE IFDHCloseChannel ( DWORD Lun )
{
    printf("IFDHCloseChannel %ld\n", Lun);
    return IFD_SUCCESS;
}

static RESPONSECODE card_state_change(DWORD Lun, int timeout)
{
    usleep(timeout * 1000);
    return IFD_RESPONSE_TIMEOUT;
}

RESPONSECODE IFDHGetCapabilities ( DWORD Lun, DWORD Tag,
                                   PDWORD Length, PUCHAR Value )
{
    printf("IFDHGetCapabilities %ld %#lx\n", Lun, Tag);
    switch (Tag) {
    case TAG_IFD_ATR:
    case SCARD_ATTR_ATR_STRING:
        *Length = sizeof(ATR);
        memcpy(Value, ATR, *Length);
        break;
    case TAG_IFD_SIMULTANEOUS_ACCESS:
        *Length = 1;
        Value[0] = 1;
        break;
    case TAG_IFD_SLOTS_NUMBER:
        *Length = 1;
        Value[0] = 1;
        break;
    case TAG_IFD_POLLING_THREAD_KILLABLE:
        *Length = 1;
        Value[0] = 1;
        break;
    case TAG_IFD_POLLING_THREAD_WITH_TIMEOUT:
        *Length = sizeof(void*);
        *(void**)Value = (void*)card_state_change;
        break;

    default:
        return IFD_ERROR_TAG;
        break;
    }
    return IFD_SUCCESS;
}

RESPONSECODE IFDHSetCapabilities ( DWORD Lun, DWORD Tag,
                                   DWORD Length, PUCHAR Value )
{

    printf("IFDHSetCapabilities %ld %#lx %ld\n", Lun, Tag, Length);
    return IFD_ERROR_TAG;
}

RESPONSECODE IFDHSetProtocolParameters ( DWORD Lun, DWORD Protocol,
        UCHAR Flags, UCHAR PTS1,
        UCHAR PTS2, UCHAR PTS3)
{

    printf("IFDHSetProtocolParameters %ld %ld %#x\n", Lun, Protocol, Flags);
    if(Protocol != SCARD_PROTOCOL_T1)
        return IFD_PROTOCOL_NOT_SUPPORTED;
    return IFD_SUCCESS;
}

RESPONSECODE IFDHPowerICC ( DWORD Lun, DWORD Action,
                            PUCHAR Atr, PDWORD AtrLength )
{
    printf("IFDHPowerICC %ld Action=%#lx\n", Lun, Action);
    if(Action == IFD_POWER_UP || Action == IFD_RESET) {
        *AtrLength = sizeof(ATR);
        memcpy(Atr, ATR, *AtrLength);
    } else if(Action == IFD_POWER_DOWN) {
    } else {
        return IFD_NOT_SUPPORTED;
    }
    return IFD_SUCCESS;
}

RESPONSECODE IFDHTransmitToICC ( DWORD Lun, SCARD_IO_HEADER SendPci,
                                 PUCHAR TxBuffer, DWORD TxLength,
                                 PUCHAR RxBuffer, PDWORD RxLength,
                                 PSCARD_IO_HEADER RecvPci )
{

    printf("IFDHTransmitToICC %ld T=%ld\n", Lun, SendPci.Protocol);
    RecvPci->Protocol = SendPci.Protocol;
    //SCARD_IO_HEADER::Length is not used according to document

    int ret = virt_card_apdu_transceive(TxBuffer, TxLength, RxBuffer, RxLength);
    if(ret < 0)
        *RxLength = 0;

    return ret == 0 ? IFD_SUCCESS : IFD_COMMUNICATION_ERROR;
}

RESPONSECODE IFDHControl (DWORD Lun, DWORD dwControlCode, PUCHAR
                          TxBuffer, DWORD TxLength, PUCHAR RxBuffer, DWORD RxLength,
                          LPDWORD pdwBytesReturned)
{

    *pdwBytesReturned = 0;
    return IFD_ERROR_NOT_SUPPORTED;
}

RESPONSECODE IFDHICCPresence( DWORD Lun )
{
    return IFD_ICC_PRESENT;
}
