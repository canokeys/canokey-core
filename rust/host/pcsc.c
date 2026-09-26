/* SPDX-License-Identifier: Apache-2.0 */
/* Native PC/SC ABI only. Slot, power, APDU and session policy are in Rust.
 * Use the platform headers: DWORD differs between Linux and macOS. */
#include <ifdhandler.h>
#include <reader.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <errno.h>

int ck_pcsc_open(uint64_t lun);
int ck_pcsc_close(uint64_t lun);
int ck_pcsc_present(uint64_t lun);
int ck_pcsc_capability(uint64_t lun, uint8_t kind, uint8_t *out, size_t cap, size_t *length);
int ck_pcsc_protocol(uint64_t lun, uint8_t t1);
int ck_pcsc_power(uint64_t lun, uint8_t action, uint8_t *out, size_t cap, size_t *length);
int ck_pcsc_transmit(uint64_t lun, const uint8_t *tx, size_t n, uint8_t *rx, size_t cap, size_t *length);
/* The PC/SC daemon owns signals; only the UDP executable installs handlers. */
int ck_host_stopping(void) { return 0; }
static RESPONSECODE status(int result) {
  switch (result) {
  case 0: return IFD_SUCCESS;
  case 1: return IFD_COMMUNICATION_ERROR;
  case 2: return IFD_ERROR_INSUFFICIENT_BUFFER;
  case 3: return IFD_NOT_SUPPORTED;
  case 4: return IFD_NO_SUCH_DEVICE;
  case 5: return IFD_PROTOCOL_NOT_SUPPORTED;
  case 6: return IFD_ERROR_TAG;
  default: return IFD_COMMUNICATION_ERROR;
  }
}
RESPONSECODE IFDHCreateChannel(DWORD lun, DWORD channel) {
  (void)channel; return status(ck_pcsc_open(lun));
}
RESPONSECODE IFDHCreateChannelByName(DWORD lun, LPSTR name) {
  (void)name; return status(ck_pcsc_open(lun));
}
RESPONSECODE IFDHCloseChannel(DWORD lun) { return status(ck_pcsc_close(lun)); }
static RESPONSECODE wait_change(DWORD lun, int milliseconds) {
  if (ck_pcsc_present(lun) != 0) return IFD_NO_SUCH_DEVICE;
  if (milliseconds < 0) return IFD_COMMUNICATION_ERROR;
  struct timespec delay = {.tv_sec = milliseconds / 1000, .tv_nsec = (milliseconds % 1000) * 1000000L};
  while (nanosleep(&delay, &delay) && errno == EINTR) {}
  return IFD_RESPONSE_TIMEOUT;
}
RESPONSECODE IFDHGetCapabilities(DWORD lun, DWORD tag, PDWORD length, PUCHAR value) {
  if (!length) return IFD_COMMUNICATION_ERROR;
  size_t capacity = *length, size = 0;
  if (tag == TAG_IFD_POLLING_THREAD_WITH_TIMEOUT) {
    if (ck_pcsc_present(lun) != 0) { *length = 0; return IFD_NO_SUCH_DEVICE; }
    RESPONSECODE (*callback)(DWORD, int) = wait_change;
    *length = sizeof(callback);
    if (capacity < sizeof(callback)) return IFD_ERROR_INSUFFICIENT_BUFFER;
    if (!value) return IFD_COMMUNICATION_ERROR;
    memcpy(value, &callback, sizeof(callback));
    return IFD_SUCCESS;
  }
  uint8_t kind = 255;
  switch (tag) {
  case TAG_IFD_ATR: case SCARD_ATTR_ATR_STRING: kind = 0; break;
  case TAG_IFD_SIMULTANEOUS_ACCESS: kind = 1; break;
  case TAG_IFD_SLOTS_NUMBER: kind = 2; break;
  case TAG_IFD_POLLING_THREAD_KILLABLE: kind = 3; break;
  case TAG_IFD_THREAD_SAFE: kind = 4; break;
  }
  int result = ck_pcsc_capability(lun, kind, value, capacity, &size);
  *length = size;
  return status(result);
}
RESPONSECODE IFDHSetCapabilities(DWORD lun, DWORD tag, DWORD length, PUCHAR value) {
  (void)lun; (void)tag; (void)length; (void)value; return IFD_ERROR_TAG;
}
RESPONSECODE IFDHSetProtocolParameters(DWORD lun, DWORD protocol, UCHAR flags, UCHAR pts1, UCHAR pts2, UCHAR pts3) {
  (void)flags; (void)pts1; (void)pts2; (void)pts3;
  return status(ck_pcsc_protocol(lun, protocol == SCARD_PROTOCOL_T1));
}
RESPONSECODE IFDHPowerICC(DWORD lun, DWORD action, PUCHAR atr, PDWORD length) {
  if (!length) return IFD_COMMUNICATION_ERROR;
  uint8_t kind = action == IFD_POWER_UP ? 0 : action == IFD_POWER_DOWN ? 1 : action == IFD_RESET ? 2 : 255;
  size_t size = 0;
  int result = ck_pcsc_power(lun, kind, atr, *length, &size);
  *length = size;
  return status(result);
}
RESPONSECODE IFDHTransmitToICC(DWORD lun, SCARD_IO_HEADER send, PUCHAR tx, DWORD n,
                              PUCHAR rx, PDWORD length, PSCARD_IO_HEADER receive) {
  if (!length || !receive) return IFD_COMMUNICATION_ERROR;
  receive->Protocol = send.Protocol;
  receive->Length = sizeof(*receive);
  size_t size = 0;
  int result = ck_pcsc_transmit(lun, tx, n, rx, *length, &size);
  *length = size;
  return status(result);
}
RESPONSECODE IFDHControl(DWORD lun, DWORD code, PUCHAR tx, DWORD n, PUCHAR rx, DWORD capacity, LPDWORD returned) {
  (void)lun; (void)code; (void)tx; (void)n; (void)rx; (void)capacity;
  if (!returned) return IFD_COMMUNICATION_ERROR;
  *returned = 0; return IFD_ERROR_NOT_SUPPORTED;
}
RESPONSECODE IFDHICCPresence(DWORD lun) {
  return ck_pcsc_present(lun) == 0 ? IFD_ICC_PRESENT : IFD_ICC_NOT_PRESENT;
}
