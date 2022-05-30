#include <tusb.h>
#include <usb_descriptors.h>

#include <ctaphid.h>
#include <hid.h>
#include <kbdhid.h>

// Dispatch HID callback to ctap/kbd handlers
void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint8_t len) {
  if (instance == HID_ITF_CTAP) {
    ctap_hid_report_complete_cb(report, len);
  } else if (instance == HID_ITF_KBD) {
    kbd_hid_report_complete_cb(report, len);
  }
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
  if (instance == HID_ITF_CTAP) {
    return ctap_hid_get_report_cb(report_id, report_type, buffer, reqlen);
  } else if (instance == HID_ITF_KBD) {
    return kbd_hid_get_report_cb(report_id, report_type, buffer, reqlen);
  }
  return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer,
                           uint16_t bufsize) {
  if (instance == HID_ITF_CTAP) {
    ctap_hid_set_report_cb(report_id, report_type, buffer, bufsize);
  } else if (instance == HID_ITF_KBD) {
    kbd_hid_set_report_cb(report_id, report_type, buffer, bufsize);
  }
}
