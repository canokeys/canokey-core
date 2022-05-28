#ifndef _KBDHID_H_
#define _KBDHID_H_

#include <tusb.h>

void kbd_hid_init();
void kbd_hid_loop();

void kbd_hid_report_complete_cb(uint8_t instance, uint8_t const* report, uint8_t len);
uint16_t kbd_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen);
void kbd_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize);

#endif /* _KBDHID_H_ */