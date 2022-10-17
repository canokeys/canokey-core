#ifndef _HID_H_
#define _HID_H_

extern void tud_hid_report_complete_cb(uint8_t instance, uint8_t const* report, uint8_t len);
extern uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen);
extern void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize);

#endif /* _HID_H_ */