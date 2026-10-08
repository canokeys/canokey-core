/* SPDX-License-Identifier: Apache-2.0 */
/* POSIX cancellation must terminate in C: Rust cannot handle glibc's forced
 * unwind as a foreign exception, even when the callback uses C-unwind. */
#define _POSIX_C_SOURCE 200809L
#include <ifdhandler.h>
#include <errno.h>
#include <time.h>
extern int ck_host_pcsc_poll_valid(DWORD lun);
RESPONSECODE ck_host_pcsc_wait_change(DWORD lun, int milliseconds) {
  if (!ck_host_pcsc_poll_valid(lun)) return IFD_NO_SUCH_DEVICE;
  if (milliseconds < 0) return IFD_COMMUNICATION_ERROR;
  struct timespec delay = {.tv_sec = milliseconds / 1000,
                          .tv_nsec = (milliseconds % 1000) * 1000000L};
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
  return IFD_RESPONSE_TIMEOUT;
}
