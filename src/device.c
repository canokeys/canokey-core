// SPDX-License-Identifier: Apache-2.0
#include "common.h"
#include <apdu.h>
#include <applet-scratch.h>
#include <applets.h>
#if ENABLE_IFACE_CCID
#include <ccid.h>
#endif
#if ENABLE_IFACE_CTAPHID
#include <ctaphid.h>
#endif
#include <device-config.h>
#include <device.h>
#if ENABLE_IFACE_KBDHID
#include <kbdhid.h>
#endif
#if ENABLE_IFACE_WEBUSB
#include <webusb.h>
#endif

static volatile uint8_t touch_result;
#if ENABLE_NFC
static uint8_t has_rf;
#endif
static uint32_t last_blink, blink_timeout, blink_interval;
static enum { ON, OFF } led_status;
typedef enum { WAIT_NONE, WAIT_CCID, WAIT_CTAPHID, WAIT_DEEP, WAIT_DEEP_TOUCHED, WAIT_DEEP_CANCEL } wait_status_t;
static volatile wait_status_t wait_status;
applet_session_scratch_t applet_session_scratch;
/* Reservation is shared with USB IRQ callbacks. Cleanup is main-loop only. */
static volatile uint32_t session_owner;
#define SESSION_RESERVING UINT32_MAX
static uint8_t apdu_context_owner;

static void device_applet_context_reset(void) {
  applets_poweroff();
  apdu_response_source_clear();
  apdu_fido_chain_reset();
  apdu_rapdu_chain_reset();
  apdu_selection_reset();
}

/* Optional lifecycle hooks for ports without the bundled USB stack. */
__weak void device_usb_service(void) {}
__weak uint8_t device_usb_ready(void) { return 1; }

uint8_t device_is_blinking(void) { return blink_timeout != 0; }

void device_loop(void) {
  device_usb_service();
  if (!device_usb_ready()) return;
#if ENABLE_IFACE_CCID
  CCID_Loop();
#endif
#if ENABLE_IFACE_CTAPHID
  CTAPHID_Loop(0);
#endif
#if ENABLE_IFACE_WEBUSB
  WebUSB_Loop();
#endif
#if ENABLE_IFACE_KBDHID
  if (device_config_is_pass_enabled()) KBDHID_Loop();
#endif
}

bool device_allow_kbd_touch(void) {
  uint32_t now = device_get_tick();
  if (!device_is_blinking() &&   // applets are not waiting for touch
      now > TOUCH_AFTER_PWRON && // ignore touch for some time after power-on
      now - TOUCH_EXPIRE_TIME > last_blink && get_touch_result() != TOUCH_NO) {
    DBG_MSG("now=%u last_blink=%u\n", now, last_blink);
    return true;
  }
  return false;
}

uint8_t get_touch_result(void) {
#ifdef TEST // emulate user interaction in test mode
  testmode_emulate_user_presence();
#endif
  return touch_result;
}

void set_touch_result(uint8_t result) { touch_result = result; }

uint8_t wait_for_user_presence(uint8_t entry) {
  device_applet_session_owner_t owner = device_applet_session_owner();
  if (owner == DEVICE_APPLET_SESSION_NONE) {
    owner = entry == WAIT_ENTRY_CTAPHID ? DEVICE_APPLET_SESSION_CTAPHID : DEVICE_APPLET_SESSION_CCID;
  }

  if (wait_status == WAIT_NONE) {
    switch (entry) {
    case WAIT_ENTRY_CCID:
      wait_status = WAIT_CCID;
      break;
    case WAIT_ENTRY_CTAPHID:
      wait_status = WAIT_CTAPHID;
      break;
    }
  } else {
    // New user presence test is denied while a test is ongoing
    DBG_MSG("Denied\n");
    return USER_PRESENCE_TIMEOUT;
  }

  uint32_t start = device_get_tick();
  uint32_t last = start;
  while (get_touch_result() == TOUCH_NO) {
    if (!device_usb_ready()) {
      stop_blinking();
      wait_status = WAIT_NONE;
      return USER_PRESENCE_CANCEL;
    }
#ifdef BYPASS_USER_PRESENCE
    break;
#endif
    device_applet_session_touch(owner);
    // Keep blinking, in case other applet stops it
    start_blinking(0);
#if ENABLE_IFACE_CTAPHID
    uint8_t ctaphid_ret = CTAPHID_Loop(1);
    if (owner == DEVICE_APPLET_SESSION_CTAPHID && ctaphid_ret == LOOP_CANCEL) {
      DBG_MSG("Cancelled by host\n");
      stop_blinking();
      wait_status = WAIT_NONE;
      return USER_PRESENCE_CANCEL;
    }
#endif
    uint32_t now = device_get_tick();
    if (now - start >= 30000) {
      DBG_MSG("timeout at %u\n", now);
      stop_blinking();
      wait_status = WAIT_NONE;
      return USER_PRESENCE_TIMEOUT;
    }
    if (now - last >= 100) {
      last = now;
#if ENABLE_IFACE_CTAPHID
      if (owner == DEVICE_APPLET_SESSION_CTAPHID) CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_UPNEEDED);
#endif
    }
  }
  // Consume this touch event
  set_touch_result(TOUCH_NO);
  stop_blinking();
  wait_status = WAIT_NONE;
  return USER_PRESENCE_OK;
}

int send_keepalive_during_processing(uint8_t entry) {
#if ENABLE_IFACE_CTAPHID
  if (!device_usb_ready()) return LOOP_CANCEL;
  if (session_owner == DEVICE_APPLET_SESSION_CTAPHID || entry == WAIT_ENTRY_CTAPHID) {
    int loop_ret = CTAPHID_Loop(1);
    if (loop_ret == LOOP_CANCEL) return loop_ret;
    CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_PROCESSING);
  }
#else
  UNUSED(entry);
#endif
  switch (session_owner) {
  case DEVICE_APPLET_SESSION_CCID:
  case DEVICE_APPLET_SESSION_CTAPHID:
  case DEVICE_APPLET_SESSION_WEBUSB:
    device_applet_session_touch(session_owner);
    break;
  default:
    break;
  }
  return 0;
}

__attribute__((weak)) int strong_user_presence_test(void) {
#ifdef BYPASS_USER_PRESENCE
  return 0;
#endif
  for (int i = 0; i < 5; i++) {
    const uint8_t wait_sec = 2;
    start_blinking_interval(wait_sec, (i & 1) ? 200 : 50);
    uint32_t now, begin = device_get_tick();
    bool user_presence = false;
    do {
      if (get_touch_result() == TOUCH_SHORT) {
        user_presence = true;
        set_touch_result(TOUCH_NO);
        stop_blinking();
        // wait for some time before next user-precense test
        begin = device_get_tick();
      }
      now = device_get_tick();
    } while (now - begin < 1000 * wait_sec);
    if (!user_presence) {
      return -1;
    }
  }
  return 0;
}

#if ENABLE_NFC
void set_nfc_state(uint8_t val) { has_rf = val; }

uint8_t is_nfc(void) {
#ifdef TEST // read NFC emulation config from a file
  testmode_get_is_nfc_mode();
#endif
  return has_rf;
}
#endif

static void toggle_led(void) {
  if (led_status == ON) {
    led_off();
    led_status = OFF;
  } else {
    led_on();
    led_status = ON;
  }
}

void device_update_led(void) {
  uint32_t now = device_get_tick();
  if (now > blink_timeout) {
    stop_blinking();
  } else if (device_is_blinking() && now >= last_blink && now - last_blink >= blink_interval) {
    last_blink = now;
    toggle_led();
  }
}

void start_blinking_interval(uint8_t sec, uint32_t interval) {
  if (device_is_blinking()) return;
  last_blink = device_get_tick();
  blink_interval = interval;
  if (sec == 0) {
    blink_timeout = UINT32_MAX;
  } else {
    blink_timeout = last_blink + sec * 1000;
  }
  toggle_led();
}

void stop_blinking(void) {
  blink_timeout = 0;
  if (device_config_is_led_normally_on()) {
    led_on();
    led_status = ON;
  } else {
    led_off();
    led_status = OFF;
  }
}

void device_init(void) {
  last_blink = 0;
  stop_blinking();
  set_touch_result(TOUCH_NO);
  session_owner = DEVICE_APPLET_SESSION_NONE;
  apdu_context_owner = DEVICE_APPLET_SESSION_NONE;
}

/* Main-loop only, after USB has invalidated the old endpoint epoch. */
void device_applet_session_clear(void) {
  device_applet_context_reset();
  session_owner = DEVICE_APPLET_SESSION_NONE;
  apdu_context_owner = DEVICE_APPLET_SESSION_NONE;
  release_apdu_buffer(BUFFER_OWNER_CCID);
  release_apdu_buffer(BUFFER_OWNER_CTAPHID);
  release_apdu_buffer(BUFFER_OWNER_WEBUSB);
}

int device_applet_session_acquire(device_applet_session_owner_t owner) {
  const uint32_t previous = session_owner;
  if (owner == DEVICE_APPLET_SESSION_NONE || previous == SESSION_RESERVING || !device_usb_ready()) return -1;
  if (previous == owner) return 0;
  /* Reserve BEFORE inspecting backing. Otherwise a same-owner RX interrupt
   * can acquire the I/O buffer without changing previous, defeating the CAS.
   * IRQ contenders refuse this sentinel; no cleanup runs while it is held. */
  if (device_atomic_compare_and_swap(&session_owner, previous, SESSION_RESERVING) != 0) return -1;
  int ret = 0;
  /* No lease expiry: unfinished APDUs may retain scratch for arbitrary gaps. */
  if (previous != DEVICE_APPLET_SESSION_NONE || owner != apdu_context_owner) {
    if (previous == DEVICE_APPLET_SESSION_CTAPHID || !apdu_session_can_preempt()) ret = -1;
  }
  // Only this caller can replace SESSION_RESERVING; failed acquisition leaves
  // the old context and every resource reservation intact.
  session_owner = ret ? previous : owner;
  return ret;
}

/* Called before APDU parsing, never from a USB callback. The reservation and
 * I/O buffer prevent competing IRQs from entering while cleanup runs. */
void device_applet_session_prepare(device_applet_session_owner_t owner) {
  if (owner == DEVICE_APPLET_SESSION_CTAPHID || owner == apdu_context_owner) return;
  if (apdu_context_owner != DEVICE_APPLET_SESSION_NONE) device_applet_context_reset();
  apdu_context_owner = owner;
}

int device_applet_session_context_matches(device_applet_session_owner_t owner) {
  return apdu_context_owner == DEVICE_APPLET_SESSION_NONE || apdu_context_owner == owner;
}

void device_applet_session_touch(device_applet_session_owner_t owner) { UNUSED(owner); }

void device_applet_session_release(device_applet_session_owner_t owner) {
  /* MSG can retain an APDU source although the card context belongs to CCID. */
  if (owner == DEVICE_APPLET_SESSION_CTAPHID && apdu_response_source_active()) return;
  device_atomic_compare_and_swap(&session_owner, owner, DEVICE_APPLET_SESSION_NONE);
}

int device_applet_session_reset(device_applet_session_owner_t owner) {
  if (session_owner == DEVICE_APPLET_SESSION_NONE) {
    if (device_atomic_compare_and_swap(&session_owner, DEVICE_APPLET_SESSION_NONE, owner) != 0) return -1;
  } else if (device_applet_session_acquire(owner) != 0)
    return -1;
  device_applet_context_reset();
  apdu_context_owner = owner;
  device_applet_session_release(owner);
  return 0;
}

device_applet_session_owner_t device_applet_session_owner(void) { return session_owner; }
