#pragma once

int virt_card_apdu_transceive(
    unsigned char *txBuf, unsigned long txLen,
    unsigned char *rxBuf, unsigned long *rxLen);

void select_u2f_from_hid(void);
