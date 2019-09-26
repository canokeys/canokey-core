#include "apdu-adapter.h"
#include "ctap.h"
#include "openpgp.h"
#include "piv.h"
#include "oath.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define SHORT_LC   4
#define EXT_LC_0   4
#define EXT_LC_MSB 5
#define EXT_LC_LSB 6

enum {
    APPLET_NULL = 0,
    APPLET_FIDO,
    APPLET_OPENPGP,
    APPLET_OATH,
    APPLET_PIV,
} current_applet;

void select_u2f_from_hid(void)
{
    current_applet = APPLET_FIDO;
}

int virt_card_apdu_transceive(
    unsigned char *txBuf, unsigned long txLen,
    unsigned char *rxBuf, unsigned long *rxLen)
{
    uint16_t Lc = 0, offData = 0;
    uint32_t Le = 256;
    if (txLen < 4) {
        printf("APDU too short\n");
        return -2;
    } else if(txLen == 4) {
        // Without Lc or Le
    } else if(txLen == 5) {
        // With Le
        Le = txBuf[SHORT_LC];
        if(Le == 0)
            Le = 0x100;
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
        //return -2;
    }

    printf("Lc=%hu Le=%u\n", Lc, Le);

    if(*rxLen < Le + 2) {
        printf("RX Buffer is not large enough\n");
        if(*rxLen > 2) {
            Le = *rxLen - 2;
            printf("  set Le to %u\n", Le);
        }else
            return -1;
    }

    CAPDU c;
    RAPDU r;

    c.cla = txBuf[0];
    c.ins = txBuf[1];
    c.p1 = txBuf[2];
    c.p2 = txBuf[3];
    c.lc = Lc;
    c.le = Le;
    c.data = txBuf + offData;

    r.len = Le;
    r.data = rxBuf; 

    int ret;
    bool selecting = false;
    if (c.cla == 0x00 && c.ins == 0xA4 && c.p1 == 0x04 && c.p2 == 0x00) {
        selecting = true;
        if(c.lc == 8 && memcmp(c.data, "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8) == 0) {
            current_applet = APPLET_FIDO;
        }
        else if(c.lc >= 6 && memcmp(c.data, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
            current_applet = APPLET_OPENPGP;
        }
        else if(c.lc >= 5 && memcmp(c.data, "\xA0\x00\x00\x03\x08", 5) == 0) {
            current_applet = APPLET_PIV;
        }
        else if(c.lc >= 7 && memcmp(c.data, "\xa0\x00\x00\x05\x27\x21\x01", 7) == 0) {
            current_applet = APPLET_OATH;
        }
        else {
            current_applet = APPLET_NULL;
        }
    }
    switch(current_applet) {
        default:
            printf("No applet selected yet\n");
            r.sw = 0x6A82;
            r.len = 0;
            ret = 0;
            break;
        case APPLET_OATH:
            if(selecting) {
                r.sw = 0x9000;
                r.len = 0;
                ret = 0;
            }else{
                printf("calling oath_process_apdu\n");
                ret = oath_process_apdu(&c, &r);
                printf("oath_process_apdu ret %d\n", ret);
            }
            break;
        case APPLET_FIDO:
            printf("calling ctap_process_apdu\n");
            if ( c.cla == 0x00 && c.ins == 0xEE && c.lc == 0x04 && memcmp(c.data, "\x12\x56\xAB\xF0", 4) == 0 ) {
                printf("MAGIC REBOOT command recieved!\r\n");
                ctap_install(0);
                r.sw = 0x9000;
                r.len = 0;
                ret = 0;
            }else{
                ret = ctap_process_apdu(&c, &r);
                printf("ctap_process_apdu ret %d\n", ret);
            }
            break;
        case APPLET_OPENPGP:
            printf("calling openpgp_process_apdu\n");
            ret = openpgp_process_apdu(&c, &r);
            printf("openpgp_process_apdu ret %d\n", ret);
            break;
        case APPLET_PIV:
            printf("calling piv_process_apdu\n");
            ret = piv_process_apdu(&c, &r);
            printf("piv_process_apdu ret %d\n", ret);
            break;
    }
    if(ret == 0) {
        rxBuf[r.len] = 0xff & (r.sw >> 8);
        rxBuf[r.len+1] = 0xff & r.sw;
        *rxLen = r.len+2;
    }


    return ret;
}
