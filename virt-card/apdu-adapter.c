#include "apdu-adapter.h"
#include "u2f.h"
#include "openpgp.h"
#include "piv.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SHORT_LC   4
#define EXT_LC_0   4
#define EXT_LC_MSB 5
#define EXT_LC_LSB 6

enum {
    APPLET_NULL = 0,
    APPLET_U2F,
    APPLET_OPENPGP,
    APPLET_PIV,
} current_applet;

int virt_card_apdu_transceive(
    unsigned char *txBuf, unsigned long txLen,
    unsigned char *rxBuf, unsigned long *rxLen)
{
    uint16_t Lc = 0, offData = 0;
    uint32_t Le = 256;
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
        if(txLen == 7 + Lc + 2) {
            // With Le
            Le = ((uint16_t)txBuf[7 + Lc] << 8) | txBuf[7 + Lc + 1];
            if (Le == 0)
                Le = 0x10000;
        }else if(txLen > 7 + Lc) {
            printf("incorrect APDU length %lu\n", txLen);
            return -2;
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
    uint8_t * resp_struct = (uint8_t*) malloc(sizeof(RAPDU) + 4096);
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

    int ret;
    if (c->cla == 0x00 && c->ins == 0xA4 && c->p1 == 0x04 && c->p2 == 0x00) {
        if(c->lc == 8 && memcmp(c->data, "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8) == 0) {
            current_applet = APPLET_U2F;
        }
        else if(c->lc >= 6 && memcmp(c->data, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
            current_applet = APPLET_OPENPGP;
        }
        else if(c->lc >= 5 && memcmp(c->data, "\xA0\x00\x00\x03\x08", 5) == 0) {
            current_applet = APPLET_PIV;
        }
    }
    switch(current_applet) {
        default:
            printf("No applet selected yet\n");
            r->sw = 0x6D00;
            r->len = 0;
            ret = 0;
            break;
        case APPLET_U2F:
            printf("calling u2f_process_apdu\n");
            ret = u2f_process_apdu(c, r);
            printf("u2f_process_apdu ret %d\n", ret);
            break;
        case APPLET_OPENPGP:
            printf("calling openpgp_process_apdu\n");
            ret = openpgp_process_apdu(c, r);
            printf("openpgp_process_apdu ret %d\n", ret);
            break;
        case APPLET_PIV:
            printf("calling piv_process_apdu\n");
            ret = piv_process_apdu(c, r);
            printf("piv_process_apdu ret %d\n", ret);
            break;
    }
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
