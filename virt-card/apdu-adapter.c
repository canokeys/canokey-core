#include "apdu-adapter.h"
#include "u2f.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SHORT_LC   4
#define EXT_LC_0   4
#define EXT_LC_MSB 5
#define EXT_LC_LSB 6


int u2f_apdu_transceive(
    unsigned char *txBuf, unsigned long txLen,
    unsigned char *rxBuf, unsigned long *rxLen)
{
    uint16_t Lc = 0, offData = 0;
    uint32_t Le = 0;
    if(txLen == 4) {
        // Without Lc or Le
    } else if(txLen == 5) {
        Le = txBuf[SHORT_LC];
    } else if(txBuf[SHORT_LC] && txLen == 5+txBuf[SHORT_LC]) {
        // With Lc
        Lc = txBuf[SHORT_LC];
        offData = SHORT_LC + 1;
    } else if(txBuf[SHORT_LC] && txLen == 6+txBuf[SHORT_LC]) {
        // With Lc and Le
        Lc = txBuf[SHORT_LC];
        offData = SHORT_LC + 1;
        Le = txBuf[5+Lc];
        if(Le == 0)
            Le = 0x100;
    } else if(txLen == 7) {
        // Without Lc
        if(txBuf[EXT_LC_0] != 0) {
            printf("Le prefix not zero\n");
            return -3;
        }
        Le = ((uint16_t)txBuf[EXT_LC_MSB] << 8) | txBuf[EXT_LC_LSB];
        if (Le == 0)
            Le = 0x10000;
    } else if(txLen > 7) {
        // With Lc
        if(txBuf[EXT_LC_0] != 0) {
            printf("Lc prefix not zero\n");
            return -3;
        }
        Lc = ((uint16_t)txBuf[EXT_LC_MSB] << 8) | txBuf[EXT_LC_LSB];
        offData = EXT_LC_LSB + 1;
        if(txLen < 7 + Lc) {
            printf("Length %lu shorter than %hu+7\n", txLen, Lc);
            return -2;
        }
        if(txLen == 7 + Lc + 3) {
            // With Le
            if(txBuf[7 + Lc] != 0) {
                printf("Le prefix not zero\n");
                return -3;
            }
            Le = ((uint16_t)txBuf[7 + Lc + 1] << 8) | txBuf[7 + Lc + 2];
            if (Le == 0)
                Le = 0x10000;
        }
    } else {
        printf("Wrong length %lu\n", txLen);
        return -2;
    }

    printf("Lc=%hu Le=%u\n", Lc, Le);

    if(*rxLen < Le + 2) {
        printf("RX Buffer is not large enough\n");
        return -1;
    }

    uint8_t * cmd_struct = (uint8_t*) malloc(sizeof(CAPDU) + Lc);
    if(!cmd_struct)
        return -1;
    uint8_t * resp_struct = (uint8_t*) malloc(sizeof(RAPDU) + Le);
    if(!resp_struct) {
        free(cmd_struct);
        return -1;
    }

    CAPDU *c = (CAPDU*) cmd_struct;
    RAPDU *r = (RAPDU*) resp_struct;

    c->cla = txBuf[0];
    c->ins = txBuf[1];
    c->p1 = txBuf[2];
    c->p2 = txBuf[3];
    c->lc = Lc;
    c->le = Le;
    memcpy(c->data, txBuf + offData, Lc);

    r->len = Le;

    printf("calling u2f_process_apdu\n");
    int ret = u2f_process_apdu(c, r);
    printf("u2f_process_apdu ret %d\n", ret);
    if(ret == 0) {
        memcpy(rxBuf, r->data, r->len);
        rxBuf[r->len] = 0xff & (r->sw >> 8);
        rxBuf[r->len+1] = 0xff & r->sw;
        *rxLen = r->len+2;
    }

    free(resp_struct);
    free(cmd_struct);

    return ret;
}